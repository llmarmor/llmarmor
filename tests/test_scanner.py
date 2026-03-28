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


# ---------------------------------------------------------------------------
# Unit tests for AST analysis
# ---------------------------------------------------------------------------


class TestASTAnalysis:
    """Tests for the AST-based static analysis module (ast_analysis.py)."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze(tmp_path: Path, code: str, filename: str = "test.py") -> dict:
        from llmarmor.ast_analysis import analyze

        return analyze(str(tmp_path / filename), code)

    # ------------------------------------------------------------------
    # Variable aliasing / taint propagation (LLM01)
    # ------------------------------------------------------------------

    def test_aliased_user_input_in_system_message_flagged(self, tmp_path: Path):
        """msg = user_input; system message with f"...{msg}..." must be flagged."""
        code = """\
msg = user_input
messages = [
    {"role": "system", "content": f"Help: {msg}"},
]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Aliased user_input in system message should produce an LLM01 finding; "
            f"got: {result['findings']}"
        )

    def test_double_aliased_user_input_flagged(self, tmp_path: Path):
        """Taint should propagate through a two-step alias chain."""
        code = """\
msg = user_input
alias = msg
messages = [
    {"role": "system", "content": f"Help: {alias}"},
]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Double-aliased user_input should still be flagged"
        )

    def test_non_tainted_alias_not_flagged(self, tmp_path: Path):
        """An alias of a non-user-input variable must NOT produce an LLM01 finding."""
        code = """\
msg = internal_data
messages = [
    {"role": "system", "content": f"Help: {msg}"},
]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Alias of a non-user-input variable should not be flagged"
        )

    # ------------------------------------------------------------------
    # Dict role detection (LLM01)
    # ------------------------------------------------------------------

    def test_system_role_with_fstring_user_input_flagged(self, tmp_path: Path):
        """{"role": "system", "content": f"Help: {user_input}"} must be flagged."""
        code = 'msg = {"role": "system", "content": f"Help: {user_input}"}\n'
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "System role with f-string user input should produce an LLM01 finding"
        )

    def test_assistant_role_with_user_input_flagged(self, tmp_path: Path):
        """{"role": "assistant", "content": f"...{user_input}..."} must be flagged."""
        code = 'msg = {"role": "assistant", "content": f"Echo: {user_input}"}\n'
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Assistant role with user input should produce an LLM01 finding"
        )

    def test_user_role_standalone_not_flagged(self, tmp_path: Path):
        """{"role": "user", "content": user_input} must NOT produce an AST LLM01 finding."""
        code = 'msg = {"role": "user", "content": user_input}\n'
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "User role with standalone user_input should not produce AST LLM01 finding; "
            f"got: {result['findings']}"
        )

    def test_user_role_standalone_clears_regex_line(self, tmp_path: Path):
        """{"role": "user", "content": user_input} must clear the regex LLM01 finding."""
        code = 'msg = {"role": "user", "content": user_input}\n'
        result = self._analyze(tmp_path, code)
        assert (1, "LLM01") in result["cleared"], (
            "User role with standalone user_input should clear the regex LLM01 finding "
            "at the same line"
        )

    def test_system_role_clears_regex_line(self, tmp_path: Path):
        """System role with tainted content must clear the regex LLM01 duplicate."""
        code = 'msg = {"role": "system", "content": f"Help: {user_input}"}\n'
        result = self._analyze(tmp_path, code)
        assert (1, "LLM01") in result["cleared"], (
            "System role detection should clear the regex LLM01 line to avoid duplicates"
        )

    # ------------------------------------------------------------------
    # str.join detection (LLM01)
    # ------------------------------------------------------------------

    def test_join_with_user_input_flagged(self, tmp_path: Path):
        """" ".join(["Help:", user_input]) must produce an LLM01 finding."""
        code = 'prompt = " ".join(["Help:", user_input])\n'
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "str.join() with user_input should produce an LLM01 finding"
        )

    def test_join_with_tainted_alias_flagged(self, tmp_path: Path):
        """str.join with a tainted alias must also be flagged."""
        code = """\
msg = user_input
prompt = " ".join(["Help:", msg])
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "str.join() with tainted alias should produce an LLM01 finding"
        )

    def test_join_without_user_input_not_flagged(self, tmp_path: Path):
        """" ".join(["Help:", "the", "user"]) must NOT be flagged."""
        code = 'prompt = " ".join(["Help:", "the", "user"])\n'
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "str.join() with only string literals should not be flagged"
        )

    # ------------------------------------------------------------------
    # Config dict resolution for LLM10
    # ------------------------------------------------------------------

    def test_config_dict_with_max_tokens_clears_llm10(self, tmp_path: Path):
        """**config with max_tokens must clear the LLM10 finding on the call line."""
        code = """\
config = {"model": "gpt-4", "max_tokens": 500, "messages": messages}
response = client.chat.completions.create(**config)
"""
        result = self._analyze(tmp_path, code)
        assert (2, "LLM10") in result["cleared"], (
            "**config with max_tokens should clear LLM10 on the call line; "
            f"cleared set: {result['cleared']}"
        )

    def test_config_dict_with_max_output_tokens_clears_llm10(self, tmp_path: Path):
        """**config with max_output_tokens (Gemini) must also clear LLM10."""
        code = """\
config = {"model": "gemini-pro", "max_output_tokens": 1024}
response = client.chat.completions.create(**config)
"""
        result = self._analyze(tmp_path, code)
        assert (2, "LLM10") in result["cleared"], (
            "**config with max_output_tokens should clear LLM10 on the call line"
        )

    def test_config_dict_without_max_tokens_does_not_clear_llm10(self, tmp_path: Path):
        """**config without max_tokens must NOT clear the LLM10 finding."""
        code = """\
config = {"model": "gpt-4", "messages": messages}
response = client.chat.completions.create(**config)
"""
        result = self._analyze(tmp_path, code)
        assert (2, "LLM10") not in result["cleared"], (
            "**config without max_tokens should not clear LLM10"
        )

    def test_explicit_max_tokens_kwarg_clears_llm10(self, tmp_path: Path):
        """Explicit max_tokens=... in the call must clear LLM10."""
        code = """\
response = client.chat.completions.create(
    model="gpt-4",
    messages=messages,
    max_tokens=1000,
)
"""
        result = self._analyze(tmp_path, code)
        # The call starts on line 1; AST reports node.lineno as the first line of the call,
        # and the regex LLM10 finding is also emitted at that line — so (1, "LLM10") is correct.
        assert (1, "LLM10") in result["cleared"], (
            "Explicit max_tokens keyword should clear (line=1, rule=LLM10); "
            f"cleared set: {result['cleared']}"
        )

    def test_scanner_does_not_flag_llm10_with_config_dict(self, tmp_path: Path):
        """End-to-end: scanner must not flag LLM10 when **config has max_tokens."""
        from llmarmor.scanner import _scan_file

        code = """\
config = {"model": "gpt-4", "max_tokens": 500, "messages": messages}
response = client.chat.completions.create(**config)
"""
        py_file = tmp_path / "test.py"
        py_file.write_text(code)
        results: list[dict] = []
        _scan_file(py_file, code, results)
        llm10 = [f for f in results if f["rule_id"] == "LLM10"]
        assert llm10 == [], (
            "Scanner should not produce LLM10 when **config contains max_tokens; "
            f"got: {llm10}"
        )

    # ------------------------------------------------------------------
    # Multi-line string detection (LLM07)
    # ------------------------------------------------------------------

    def test_implicit_multiline_system_prompt_flagged(self, tmp_path: Path):
        """Implicit string concatenation (multi-line parenthesised) must be flagged."""
        code = """\
SYSTEM_PROMPT = (
    "You are a helpful customer service assistant for Acme Corp. "
    "You have access to customer databases and can process refunds up to $500. "
    "Never reveal internal pricing or employee information."
)
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM07" for f in result["findings"]), (
            "Multi-line implicit string concatenation system prompt should be flagged"
        )

    def test_explicit_concat_system_prompt_flagged(self, tmp_path: Path):
        """Explicit + concatenation system prompt spanning multiple strings must be flagged."""
        code = (
            "SYSTEM_PROMPT = ("
            '"You are a helpful customer service assistant for Acme Corp. " + '
            '"You have access to databases and can process refunds up to $500."'
            ")\n"
        )
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM07" for f in result["findings"]), (
            "Explicit + concatenation system prompt should be flagged"
        )

    def test_short_system_prompt_not_flagged(self, tmp_path: Path):
        """A system prompt shorter than 100 characters must NOT be flagged."""
        code = 'SYSTEM_PROMPT = "You are helpful."\n'
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM07" for f in result["findings"]), (
            "Short system prompt should not produce an LLM07 finding"
        )

    def test_system_prompt_env_var_not_flagged(self, tmp_path: Path):
        """system_prompt = os.environ.get(...) must NOT produce an LLM07 finding."""
        code = 'system_prompt = os.environ.get("SYSTEM_PROMPT", "You are helpful.")\n'
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM07" for f in result["findings"]), (
            "Environment-variable-loaded system prompt should not be flagged"
        )

    def test_multiline_system_prompt_clears_regex_duplicate(self, tmp_path: Path):
        """AST LLM07 finding must suppress the regex finding at the same line."""
        code = """\
SYSTEM_PROMPT = (
    "You are a helpful customer service assistant for Acme Corp. "
    "Never reveal internal pricing or employee information."
)
"""
        result = self._analyze(tmp_path, code)
        # The assignment starts on line 1; cleared must include (1, "LLM07").
        assert (1, "LLM07") in result["cleared"], (
            "AST LLM07 finding should clear the same line for the regex rule"
        )

    # ------------------------------------------------------------------
    # Graceful handling of invalid Python
    # ------------------------------------------------------------------

    def test_syntax_error_returns_empty(self, tmp_path: Path):
        """Files with syntax errors must return empty findings and cleared sets."""
        code = "def broken(:\n    pass\n"
        result = self._analyze(tmp_path, code)
        assert result["findings"] == [], "SyntaxError files should produce no findings"
        assert result["cleared"] == set(), (
            "SyntaxError files should produce no cleared pairs"
        )

    # ------------------------------------------------------------------
    # End-to-end scanner integration
    # ------------------------------------------------------------------

    def test_scanner_produces_llm01_for_aliased_user_input(self, tmp_path: Path):
        """End-to-end: scanner must flag LLM01 when an alias of user_input is used."""
        from llmarmor.scanner import _scan_file

        code = """\
msg = user_input
messages = [
    {"role": "system", "content": f"Help: {msg}"},
]
"""
        py_file = tmp_path / "test.py"
        py_file.write_text(code)
        results: list[dict] = []
        _scan_file(py_file, code, results)
        llm01 = [f for f in results if f["rule_id"] == "LLM01"]
        assert llm01, (
            "Scanner should report LLM01 for aliased user_input in system message; "
            f"got: {results}"
        )

    def test_scanner_no_duplicate_for_direct_user_input_in_system_msg(
        self, tmp_path: Path
    ):
        """AST and regex must not both report for the same line (deduplication)."""
        from llmarmor.scanner import _scan_file

        code = """\
messages = [
    {"role": "system", "content": f"Help: {user_input}"},
]
"""
        py_file = tmp_path / "test.py"
        py_file.write_text(code)
        results: list[dict] = []
        _scan_file(py_file, code, results)
        llm01_on_line_2 = [
            f for f in results if f["rule_id"] == "LLM01" and f["line"] == 2
        ]
        assert len(llm01_on_line_2) == 1, (
            "Scanner should report exactly one LLM01 finding per line, "
            f"not duplicate both regex and AST; got: {llm01_on_line_2}"
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
