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

    def test_detects_fstring_with_user_input(self, tmp_path: Path):
        findings = check_prompt_injection(tmp_path / "vuln.py", self.VULNERABLE_CODE)
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "LLM01"
        assert findings[0]["severity"] == "CRITICAL"

    def test_no_finding_on_safe_code(self, tmp_path: Path):
        findings = check_prompt_injection(tmp_path / "safe.py", self.SAFE_CODE)
        assert findings == []


class TestSensitiveInfo:
    OPENAI_KEY = 'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"'
    ANTHROPIC_KEY = 'ANTHROPIC_KEY = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu"'
    GOOGLE_KEY = 'GOOGLE_KEY = "AIzaSyAbcdefghijklmnopqrstuvwxyz01234567890"'
    COMMENT_LINE = '# sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234'

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
        assert findings[0]["severity"] == "HIGH"

    def test_no_finding_for_env_var_prompt(self, tmp_path: Path):
        findings = check_system_prompt_leak(tmp_path / "safe.py", self.SAFE_CODE)
        assert findings == []


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
