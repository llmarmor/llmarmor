"""Tests for the LLM Armor scanner and individual rules."""

import shutil
from pathlib import Path

import pytest

from llmarmor.scanner import run_scan
from llmarmor.rules.llm01_prompt_injection import check_prompt_injection
from llmarmor.rules.llm02_sensitive_info import check_sensitive_info
from llmarmor.rules.llm07_system_prompt_leak import check_system_prompt_leak
from llmarmor.rules.llm10_unbounded_consumption import check_unbounded_consumption

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


def test_scan_vulnerable_app():
    """Scanner must detect findings in tests/fixtures/vulnerable_app.py."""
    findings = run_scan(str(FIXTURES_DIR))
    assert findings, "Expected findings from vulnerable_app.py but got none"

    rule_ids_found = {f["rule_id"] for f in findings}
    assert "LLM01" in rule_ids_found, "Expected LLM01 (Prompt Injection) finding"
    assert "LLM02" in rule_ids_found, "Expected LLM02 (Sensitive Info) finding"
    assert "LLM07" in rule_ids_found, "Expected LLM07 (System Prompt Leak) finding"
    assert "LLM10" in rule_ids_found, "Expected LLM10 (Unbounded Consumption) finding"


def test_scan_safe_app(tmp_path: Path):
    """Scanner must produce zero findings for the safe fixture."""
    safe_file = tmp_path / "safe_app.py"
    shutil.copy(FIXTURES_DIR / "safe_app.py", safe_file)

    findings = run_scan(str(tmp_path))
    assert findings == [], f"Expected no findings for safe_app.py but got: {findings}"


# ---------------------------------------------------------------------------
# Unit tests for individual rule functions
# ---------------------------------------------------------------------------


class TestPromptInjection:
    VULNERABLE_CODE = '''\
messages=[
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": f"Help the user with: {user_input}"},
]
'''
    SAFE_CODE = '''\
messages=[
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": validated_input},
]
'''
    # Pattern 1: safe — user_input passed as a standalone value (no interpolation)
    SAFE_CODE_STANDALONE_USER_INPUT = '''\
messages=[
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": user_input},
]
'''
    # String concatenation into a prompt variable
    CONCAT_VULNERABLE_CODE = 'prompt = "Help: " + user_input\n'

    def test_detects_fstring_with_user_input(self, tmp_path: Path):
        findings = check_prompt_injection(tmp_path / "vuln.py", self.VULNERABLE_CODE)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"
        assert findings[0]["severity"] == "CRITICAL"

    def test_no_finding_on_safe_code(self, tmp_path: Path):
        findings = check_prompt_injection(tmp_path / "safe.py", self.SAFE_CODE)
        assert findings == []

    def test_no_finding_when_user_input_is_standalone_content_value(self, tmp_path: Path):
        """Pattern 1: 'content': user_input (no f-string, no concatenation) is safe."""
        findings = check_prompt_injection(
            tmp_path / "safe.py", self.SAFE_CODE_STANDALONE_USER_INPUT
        )
        assert findings == [], (
            "Passing user_input as a standalone 'content' value should NOT be flagged; "
            f"got: {findings}"
        )

    def test_detects_string_concatenation_with_user_input(self, tmp_path: Path):
        """String concatenation of user input into a prompt variable must be flagged."""
        findings = check_prompt_injection(tmp_path / "vuln.py", self.CONCAT_VULNERABLE_CODE)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"
        assert findings[0]["severity"] == "CRITICAL"

    def test_detects_triple_quoted_fstring(self, tmp_path: Path):
        """Triple-quoted f-strings with user input near prompt context must be flagged."""
        code = '''\
messages=[
    {"role": "system", "content": f"""You are a helpful assistant. User said: {user_input}"""},
]
'''
        findings = check_prompt_injection(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"

    def test_skips_comment_lines(self, tmp_path: Path):
        """Lines starting with # must not be flagged even if they contain f-string patterns."""
        code = '''\
messages=[
    # {"role": "user", "content": f"Help: {user_input}"},
    {"role": "user", "content": user_input},
]
'''
        findings = check_prompt_injection(tmp_path / "safe.py", code)
        assert findings == [], f"Comment lines should not be flagged; got: {findings}"

    def test_detects_format_method_with_user_input(self, tmp_path: Path):
        """.format() with user input near prompt context must be flagged."""
        code = '''\
messages=[
    {"role": "system", "content": "You are a helpful assistant."},
]
prompt = "Help the user with: {}".format(user_input)
'''
        findings = check_prompt_injection(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"

    def test_detects_percent_formatting_with_user_input(self, tmp_path: Path):
        """Percent-formatting with user input near prompt context must be flagged."""
        code = '''\
messages=[
    {"role": "system", "content": "You are a helpful assistant."},
]
content = "Help the user with: %s" % user_input
'''
        findings = check_prompt_injection(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"

    def test_detects_langchain_prompt_template(self, tmp_path: Path):
        """LangChain PromptTemplate with user input variable must be flagged."""
        code = 'template = PromptTemplate.from_template("Help the user: {user_input}")\n'
        findings = check_prompt_injection(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"

    def test_detects_langchain_prompt_template_with_input_variables(self, tmp_path: Path):
        """LangChain PromptTemplate(template=...) with user input placeholder flagged."""
        code = (
            'pt = PromptTemplate(template="Translate: {user_message}", '
            'input_variables=["user_message"])\n'
        )
        findings = check_prompt_injection(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"

    def test_no_finding_for_format_without_prompt_context(self, tmp_path: Path):
        """.format() with user input far from any prompt context should NOT be flagged."""
        code = 'label = "Hello, {}".format(user_input)\n'
        findings = check_prompt_injection(tmp_path / "safe.py", code)
        assert findings == [], (
            ".format() without nearby prompt context should not be flagged; "
            f"got: {findings}"
        )


class TestSensitiveInfo:
    OPENAI_KEY = 'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
    ANTHROPIC_KEY = 'ANTHROPIC_KEY = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu"'
    GOOGLE_KEY = 'GOOGLE_KEY = "AIzaSyAbcdefghijklmnopqrstuvwxyz01234567890"'
    COMMENT_LINE = '# sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234'
    HF_TOKEN = 'HF_TOKEN = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"'

    def test_detects_openai_key(self, tmp_path: Path):
        findings = check_sensitive_info(tmp_path / "vuln.py", self.OPENAI_KEY)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"

    def test_detects_anthropic_key(self, tmp_path: Path):
        findings = check_sensitive_info(tmp_path / "vuln.py", self.ANTHROPIC_KEY)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"

    def test_detects_google_key(self, tmp_path: Path):
        findings = check_sensitive_info(tmp_path / "vuln.py", self.GOOGLE_KEY)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"

    def test_skips_comment_lines(self, tmp_path: Path):
        findings = check_sensitive_info(tmp_path / "safe.py", self.COMMENT_LINE)
        assert findings == []

    def test_detects_huggingface_token(self, tmp_path: Path):
        """Hugging Face hf_ token must be flagged as LLM02."""
        findings = check_sensitive_info(tmp_path / "vuln.py", self.HF_TOKEN)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"
        assert "Hugging Face" in findings[0]["description"]

    def test_skips_test_variable(self, tmp_path: Path):
        """Variables with 'test' in the name must not be flagged."""
        line = 'test_api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"test_ variables should not be flagged; got: {findings}"

    def test_skips_fake_variable(self, tmp_path: Path):
        """Variables with 'fake' in the name must not be flagged."""
        line = 'FAKE_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"FAKE_ variables should not be flagged; got: {findings}"

    def test_skips_mock_variable(self, tmp_path: Path):
        """Variables with 'mock' in the name must not be flagged."""
        line = 'mock_openai_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"mock_ variables should not be flagged; got: {findings}"

    def test_skips_example_variable(self, tmp_path: Path):
        """Variables with 'example' in the name must not be flagged."""
        line = 'EXAMPLE_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"EXAMPLE_ variables should not be flagged; got: {findings}"

    def test_skips_dummy_variable(self, tmp_path: Path):
        """Variables with 'dummy' in the name must not be flagged."""
        line = 'dummy_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"dummy_ variables should not be flagged; got: {findings}"

    def test_skips_placeholder_variable(self, tmp_path: Path):
        """Variables with 'placeholder' in the name must not be flagged."""
        line = 'placeholder_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"placeholder_ variables should not be flagged; got: {findings}"

    def test_does_not_flag_short_sk_token(self, tmp_path: Path):
        """Short sk- tokens (< 20 chars after prefix) such as SKUs must not be flagged."""
        line = 'sku = "sk-100"\n'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"Short sk- tokens should not be flagged; got: {findings}"


class TestSystemPromptLeak:
    VULNERABLE_CODE = (
        'SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. '
        'You have access to customer databases and can process refunds up to $500."'
    )
    SAFE_CODE = 'system_prompt = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")'

    def test_detects_hardcoded_system_prompt(self, tmp_path: Path):
        findings = check_system_prompt_leak(tmp_path / "vuln.py", self.VULNERABLE_CODE)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM07"
        assert findings[0]["severity"] == "INFO"

    def test_no_finding_for_env_var_prompt(self, tmp_path: Path):
        findings = check_system_prompt_leak(tmp_path / "safe.py", self.SAFE_CODE)
        assert findings == []

    def test_no_finding_for_short_prompt(self, tmp_path: Path):
        """Prompts shorter than 100 characters must not be flagged."""
        short_prompt = 'SYSTEM_PROMPT = "You are a helpful assistant. Be concise."'
        findings = check_system_prompt_leak(tmp_path / "safe.py", short_prompt)
        assert findings == [], (
            "Short system prompts (< 100 chars) should not be flagged; "
            f"got: {findings}"
        )

    def test_skips_comment_lines(self, tmp_path: Path):
        """Lines starting with # must not be flagged even if they look like system prompts."""
        code = (
            '# SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. '
            'You have access to customer databases and can process refunds up to $500."\n'
        )
        findings = check_system_prompt_leak(tmp_path / "safe.py", code)
        assert findings == [], f"Comment lines should not be flagged; got: {findings}"


class TestUnboundedConsumption:
    VULNERABLE_CODE = '''\
response = client.chat.completions.create(
    model="gpt-4",
    messages=messages,
)
'''
    SAFE_CODE = '''\
response = client.chat.completions.create(
    model="gpt-4",
    messages=messages,
    max_tokens=1000,
)
'''

    def test_detects_missing_max_tokens(self, tmp_path: Path):
        findings = check_unbounded_consumption(tmp_path / "vuln.py", self.VULNERABLE_CODE)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM10"
        assert findings[0]["severity"] == "MEDIUM"

    def test_no_finding_when_max_tokens_set(self, tmp_path: Path):
        findings = check_unbounded_consumption(tmp_path / "safe.py", self.SAFE_CODE)
        assert findings == []

    def test_no_finding_for_images_generate(self, tmp_path: Path):
        """images.generate is not an LLM text call — should not trigger LLM10."""
        code = '''\
response = client.images.generate(
    model="dall-e-3",
    prompt="A sunset over the ocean",
    n=1,
)
'''
        findings = check_unbounded_consumption(tmp_path / "img.py", code)
        assert findings == [], f"images.generate should not trigger LLM10: {findings}"

    def test_no_finding_when_max_output_tokens_set(self, tmp_path: Path):
        """max_output_tokens (Google Gemini API) must count as token limit present."""
        code = '''\
response = client.chat.completions.create(
    model="gemini-pro",
    messages=messages,
    max_output_tokens=1000,
)
'''
        findings = check_unbounded_consumption(tmp_path / "safe.py", code)
        assert findings == [], (
            f"max_output_tokens should satisfy the token limit check; got: {findings}"
        )

    def test_detects_litellm_completion(self, tmp_path: Path):
        """litellm.completion() without max_tokens must be flagged."""
        code = '''\
response = litellm.completion(
    model="gpt-4",
    messages=messages,
)
'''
        findings = check_unbounded_consumption(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM10"

    def test_no_finding_for_litellm_with_max_tokens(self, tmp_path: Path):
        """litellm.completion() with max_tokens set must not be flagged."""
        code = '''\
response = litellm.completion(
    model="gpt-4",
    messages=messages,
    max_tokens=500,
)
'''
        findings = check_unbounded_consumption(tmp_path / "safe.py", code)
        assert findings == []

    def test_description_notes_kwargs_when_present(self, tmp_path: Path):
        """When **kwargs is in the call block, description must mention it."""
        code = '''\
response = client.chat.completions.create(
    model="gpt-4",
    messages=messages,
    **kwargs,
)
'''
        findings = check_unbounded_consumption(tmp_path / "vuln.py", code)
        assert len(findings) >= 1
        assert "kwargs" in findings[0]["description"], (
            "Description should mention kwargs when **kwargs is present in the call block"
        )
