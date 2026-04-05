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
        assert findings[0]["severity"] == "HIGH"

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
        assert findings[0]["severity"] == "HIGH"

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
        """alias of input()-tainted var in system message must be flagged."""
        code = """\
user_input = input("Enter query: ")
msg = user_input
messages = [
    {"role": "system", "content": f"Help: {msg}"},
]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Aliased input()-tainted variable in system message should produce an LLM01 finding; "
            f"got: {result['findings']}"
        )

    def test_double_aliased_user_input_flagged(self, tmp_path: Path):
        """Taint should propagate through a two-step alias chain from input()."""
        code = """\
user_input = input("Enter query: ")
msg = user_input
alias = msg
messages = [
    {"role": "system", "content": f"Help: {alias}"},
]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Double-aliased input()-sourced variable should still be flagged"
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
        """request-sourced var in system role f-string must be flagged by AST."""
        code = """\
user_input = request.json["prompt"]
msg = {"role": "system", "content": f"Help: {user_input}"}
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "System role with f-string containing request-sourced variable should produce an LLM01 finding"
        )

    def test_assistant_role_with_user_input_flagged(self, tmp_path: Path):
        """request-sourced var in assistant role must be flagged by AST."""
        code = """\
user_input = request.form.get("prompt")
msg = {"role": "assistant", "content": f"Echo: {user_input}"}
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Assistant role with request-sourced variable should produce an LLM01 finding"
        )

    def test_user_role_standalone_not_flagged(self, tmp_path: Path):
        """{"role": "user", "content": tainted_var} must only produce an INFO-level finding (hidden by default)."""
        code = """\
user_input = input("prompt")
msg = {"role": "user", "content": user_input}
"""
        result = self._analyze(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert all(f["severity"] == "INFO" for f in llm01), (
            "User role with standalone tainted variable should only produce INFO-level LLM01 finding; "
            f"got: {result['findings']}"
        )

    def test_user_role_standalone_clears_regex_line(self, tmp_path: Path):
        """{"role": "user", "content": tainted_name} must clear any regex LLM01 on that line."""
        code = """\
user_input = input("prompt")
msg = {"role": "user", "content": user_input}
"""
        result = self._analyze(tmp_path, code)
        assert (2, "LLM01") in result["cleared"], (
            "User role with standalone tainted variable should clear the regex LLM01 finding "
            "at the same line"
        )

    def test_system_role_clears_regex_line(self, tmp_path: Path):
        """System role with tainted content must clear the regex LLM01 duplicate."""
        code = """\
user_input = request.json["prompt"]
msg = {"role": "system", "content": f"Help: {user_input}"}
"""
        result = self._analyze(tmp_path, code)
        assert (2, "LLM01") in result["cleared"], (
            "System role detection should clear the regex LLM01 line to avoid duplicates"
        )

    # ------------------------------------------------------------------
    # str.join detection (LLM01)
    # ------------------------------------------------------------------

    def test_join_with_user_input_flagged(self, tmp_path: Path):
        """" ".join() with an input()-sourced element must produce an LLM01 finding."""
        code = """\
user_input = input("query")
prompt = " ".join(["Help:", user_input])
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "str.join() with input()-sourced variable should produce an LLM01 finding"
        )

    def test_join_with_tainted_alias_flagged(self, tmp_path: Path):
        """str.join with a tainted alias must also be flagged."""
        code = """\
user_input = input("query")
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
        """End-to-end: scanner must flag LLM01 when an alias of a tainted source is used."""
        from llmarmor.scanner import _scan_file

        code = """\
user_input = input("Enter query: ")
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
user_input = input("query")
messages = [
    {"role": "system", "content": f"Help: {user_input}"},
]
"""
        py_file = tmp_path / "test.py"
        py_file.write_text(code)
        results: list[dict] = []
        _scan_file(py_file, code, results)
        llm01_on_line_3 = [
            f for f in results if f["rule_id"] == "LLM01" and f["line"] == 3
        ]
        assert len(llm01_on_line_3) == 1, (
            "Scanner should report exactly one LLM01 finding per line, "
            f"not duplicate both regex and AST; got: {llm01_on_line_3}"
        )

    # ------------------------------------------------------------------
    # Safe-assignment de-taint tests (false-positive prevention)
    # ------------------------------------------------------------------

    def test_user_prompt_hardcoded_string_not_flagged(self, tmp_path: Path):
        """user_prompt = "hardcoded" must NOT be treated as user-controlled."""
        code = """\
user_prompt = "You are a helpful assistant"
messages = [{"role": "system", "content": f"{user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Hardcoded string assigned to user_prompt should not be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_config_get_not_flagged(self, tmp_path: Path):
        """user_prompt = config.get("prompt") must NOT be flagged."""
        code = """\
user_prompt = config.get("default_prompt")
messages = [{"role": "system", "content": f"Context: {user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "config.get() assignment to user_prompt should not be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_db_fetch_not_flagged(self, tmp_path: Path):
        """user_prompt = db.fetch_prompt(id) must NOT be flagged."""
        code = """\
user_prompt = db.fetch_prompt(prompt_id)
messages = [{"role": "system", "content": f"Help: {user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "db.fetch_prompt() assignment to user_prompt should not be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_os_environ_not_flagged(self, tmp_path: Path):
        """user_prompt = os.environ["PROMPT"] must NOT be flagged."""
        code = """\
user_prompt = os.environ["PROMPT"]
messages = [{"role": "system", "content": f"{user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "os.environ[] assignment to user_prompt should not be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_os_getenv_not_flagged(self, tmp_path: Path):
        """user_prompt = os.getenv("PROMPT") must NOT be flagged."""
        code = """\
user_prompt = os.getenv("PROMPT")
messages = [{"role": "system", "content": f"{user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "os.getenv() assignment to user_prompt should not be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_settings_attr_not_flagged(self, tmp_path: Path):
        """user_prompt = settings.DEFAULT_PROMPT must NOT be flagged."""
        code = """\
user_prompt = settings.DEFAULT_PROMPT
messages = [{"role": "system", "content": f"{user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "settings.DEFAULT_PROMPT assignment to user_prompt should not be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_from_request_json_flagged(self, tmp_path: Path):
        """user_prompt = request.json["prompt"] MUST be flagged."""
        code = """\
user_prompt = request.json["prompt"]
messages = [{"role": "system", "content": f"Help: {user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "request.json[] assignment to user_prompt should be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_from_request_form_flagged(self, tmp_path: Path):
        """user_prompt = request.form.get("prompt") MUST be flagged."""
        code = """\
user_prompt = request.form.get("prompt")
messages = [{"role": "system", "content": f"Help: {user_prompt}"}]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "request.form.get() assignment to user_prompt should be flagged; "
            f"got: {result['findings']}"
        )

    def test_user_prompt_as_function_parameter_flagged(self, tmp_path: Path):
        """def handle(user_prompt): … used in f-string MUST be flagged."""
        code = """\
def handle(user_prompt):
    messages = [{"role": "system", "content": f"Help: {user_prompt}"}]
    return messages
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "user_prompt function parameter used in system message should be flagged; "
            f"got: {result['findings']}"
        )

    # ------------------------------------------------------------------
    # Source-based taint seeding — new sources (LLM01)
    # ------------------------------------------------------------------

    def test_input_builtin_taints_variable(self, tmp_path: Path):
        """data = input() must seed taint; usage in system role must be flagged."""
        code = """\
data = input("Enter message: ")
messages = [{"role": "system", "content": f"Help: {data}"}]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Variable assigned from input() used in system role should be flagged; "
            f"got: {result['findings']}"
        )

    def test_sys_argv_taints_variable(self, tmp_path: Path):
        """data = sys.argv[1] must seed taint; usage in system role must be flagged."""
        code = """\
data = sys.argv[1]
messages = [{"role": "system", "content": f"Help: {data}"}]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Variable assigned from sys.argv[] used in system role should be flagged; "
            f"got: {result['findings']}"
        )

    def test_websocket_receive_taints_variable(self, tmp_path: Path):
        """data = websocket.receive() must seed taint; usage in system role must be flagged."""
        code = """\
data = websocket.receive()
messages = [{"role": "system", "content": f"Help: {data}"}]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Variable assigned from websocket.receive() used in system role should be flagged; "
            f"got: {result['findings']}"
        )

    def test_websocket_recv_taints_variable(self, tmp_path: Path):
        """data = ws.recv() (alternate spelling) must also seed taint."""
        code = """\
data = ws.recv()
messages = [{"role": "system", "content": f"Help: {data}"}]
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Variable assigned from ws.recv() used in system role should be flagged; "
            f"got: {result['findings']}"
        )

    def test_safe_sources_do_not_taint(self, tmp_path: Path):
        """config.get(), os.environ, db call, and string literal must NOT taint."""
        code = """\
p1 = config.get("prompt")
p2 = os.environ["PROMPT"]
p3 = db.fetch("prompt")
p4 = "hardcoded"
messages = [
    {"role": "system", "content": f"a:{p1} b:{p2} c:{p3} d:{p4}"},
]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "config, os.environ, db, and string literals should not taint variables; "
            f"got: {result['findings']}"
        )

    def test_sanitized_tainted_value_not_propagated(self, tmp_path: Path):
        """validated = sanitize(tainted) must NOT propagate taint (no Call propagation)."""
        code = """\
raw = input("query")
validated = sanitize(raw)
messages = [{"role": "system", "content": f"Help: {validated}"}]
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Taint must not propagate through function calls; validated should be clean; "
            f"got: {result['findings']}"
        )

    def test_async_function_parameters_tainted(self, tmp_path: Path):
        """async def handler(msg): … must treat msg as tainted (WebSocket handler)."""
        code = """\
async def handler(msg):
    messages = [{"role": "system", "content": f"Process: {msg}"}]
    return messages
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Async function parameters should be treated as tainted sources; "
            f"got: {result['findings']}"
        )

    # ------------------------------------------------------------------
    # collect_tainted() public API
    # ------------------------------------------------------------------

    def test_collect_tainted_from_input(self, tmp_path: Path):
        """collect_tainted() must include variables assigned from input()."""
        import ast as _ast

        from llmarmor.ast_analysis import collect_tainted

        code = "data = input('q')\nalias = data\n"
        tree = _ast.parse(code)
        tainted = collect_tainted(tree)
        assert "data" in tainted, f"data should be tainted; got: {tainted}"
        assert "alias" in tainted, f"alias should be tainted (propagated); got: {tainted}"

    def test_collect_tainted_from_request(self, tmp_path: Path):
        """collect_tainted() must include variables assigned from request sources."""
        import ast as _ast

        from llmarmor.ast_analysis import collect_tainted

        code = "msg = request.json['prompt']\n"
        tree = _ast.parse(code)
        tainted = collect_tainted(tree)
        assert "msg" in tainted, f"msg should be tainted; got: {tainted}"

    def test_collect_tainted_from_function_params(self, tmp_path: Path):
        """collect_tainted() must include function parameters."""
        import ast as _ast

        from llmarmor.ast_analysis import collect_tainted

        code = "def handle(user_input, ctx):\n    pass\n"
        tree = _ast.parse(code)
        tainted = collect_tainted(tree)
        assert "user_input" in tainted, f"user_input param should be tainted; got: {tainted}"
        assert "ctx" in tainted, f"ctx param should be tainted; got: {tainted}"

    def test_collect_tainted_safe_sources_excluded(self, tmp_path: Path):
        """collect_tainted() must NOT include variables from safe sources."""
        import ast as _ast

        from llmarmor.ast_analysis import collect_tainted

        code = """\
a = config.get("x")
b = os.environ["KEY"]
c = "literal"
d = db.fetch(1)
"""
        tree = _ast.parse(code)
        tainted = collect_tainted(tree)
        assert not tainted, f"No variables should be tainted from safe sources; got: {tainted}"

    # ------------------------------------------------------------------
    # Fix 2: Plain variable in dict content must never be flagged (LLM01)
    # ------------------------------------------------------------------

    def test_system_role_plain_name_not_flagged(self, tmp_path: Path):
        """{"role": "system", "content": system} must only produce INFO (hidden by default).

        A plain variable reference is not string interpolation — no injection
        of instructions mixed with user data is occurring.  An INFO finding is
        emitted so --verbose can surface it.
        """
        code = """\
def handle(system, user):
    msg = {"role": "system", "content": system}
    return msg
"""
        result = self._analyze(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert all(f["severity"] == "INFO" for f in llm01), (
            '{"role": "system", "content": system} (plain variable) should only produce INFO-level LLM01; '
            f"got: {result['findings']}"
        )

    def test_user_role_plain_name_not_flagged(self, tmp_path: Path):
        """{"role": "user", "content": user} must only produce INFO (hidden by default)."""
        code = """\
def handle(user):
    msg = {"role": "user", "content": user}
    return msg
"""
        result = self._analyze(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert all(f["severity"] == "INFO" for f in llm01), (
            '{"role": "user", "content": user} (plain variable) should only produce INFO-level LLM01; '
            f"got: {result['findings']}"
        )

    def test_system_role_fstring_tainted_flagged(self, tmp_path: Path):
        """{"role": "system", "content": f"Help: {tainted_var}"} must be flagged."""
        code = """\
tainted_var = input("Enter: ")
msg = {"role": "system", "content": f"Help: {tainted_var}"}
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "f-string interpolation of tainted var in system role should produce LLM01; "
            f"got: {result['findings']}"
        )

    def test_system_role_concat_tainted_flagged(self, tmp_path: Path):
        """{"role": "system", "content": "Help: " + tainted_var} must be flagged."""
        code = """\
tainted_var = input("Enter: ")
msg = {"role": "system", "content": "Help: " + tainted_var}
"""
        result = self._analyze(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "String concatenation of tainted var in system role should produce LLM01; "
            f"got: {result['findings']}"
        )

    def test_messages_list_plain_names_not_flagged(self, tmp_path: Path):
        """List of dicts with plain variable content must only produce INFO findings.

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        """
        code = """\
def handle(system, user):
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    return messages
"""
        result = self._analyze(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert all(f["severity"] == "INFO" for f in llm01), (
            "messages list with plain variable content should only produce INFO-level LLM01; "
            f"got: {result['findings']}"
        )

    # ------------------------------------------------------------------
    # Fix 3: Eval/test file context detection
    # ------------------------------------------------------------------

    def test_eval_path_downgrades_llm01_to_info(self, tmp_path: Path):
        """LLM01 findings in a file under an 'evals/' path must be INFO severity."""
        code = """\
tainted_var = input("Enter: ")
msg = {"role": "system", "content": f"Help: {tainted_var}"}
"""
        # Simulate a file at evals/graders.py
        from llmarmor.ast_analysis import analyze

        result = analyze(str(tmp_path / "evals" / "graders.py"), code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected at least one LLM01 finding in eval context"
        assert all(f["severity"] == "INFO" for f in llm01), (
            "LLM01 findings in eval context should be downgraded to INFO; "
            f"got severities: {[f['severity'] for f in llm01]}"
        )
        assert all(f["description"].startswith("[eval context]") for f in llm01), (
            "LLM01 descriptions in eval context should be prefixed with '[eval context]'; "
            f"got: {[f['description'][:30] for f in llm01]}"
        )

    def test_non_eval_path_keeps_llm01_critical(self, tmp_path: Path):
        """LLM01 findings in a regular app file must remain CRITICAL severity."""
        code = """\
tainted_var = input("Enter: ")
msg = {"role": "system", "content": f"Help: {tainted_var}"}
"""
        from llmarmor.ast_analysis import analyze

        result = analyze(str(tmp_path / "app" / "chat.py"), code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected at least one LLM01 finding in non-eval context"
        assert all(f["severity"] == "CRITICAL" for f in llm01), (
            "LLM01 findings in non-eval context should remain CRITICAL; "
            f"got severities: {[f['severity'] for f in llm01]}"
        )
        assert not any(f["description"].startswith("[eval context]") for f in llm01), (
            "LLM01 descriptions in non-eval context must not have '[eval context]' prefix"
        )

    # ------------------------------------------------------------------
    # Fix 1: SyntaxWarning suppression during scan
    # ------------------------------------------------------------------

    def test_syntax_warning_not_emitted_during_scan(self, tmp_path: Path):
        """Scanning a file with invalid escape sequences must not emit SyntaxWarning."""
        import warnings

        from llmarmor.scanner import _scan_file

        # '\$' is an invalid escape in Python 3.12+ and triggers SyntaxWarning
        code = 'pattern = "\\$[0-9]+"\n'
        py_file = tmp_path / "currency.py"
        py_file.write_text(code)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            results: list[dict] = []
            _scan_file(py_file, code, results)

        syntax_warnings = [w for w in recorded if issubclass(w.category, SyntaxWarning)]
        assert syntax_warnings == [], (
            f"SyntaxWarning should be suppressed during scan; got: {syntax_warnings}"
        )
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

    def test_does_not_flag_env_var_name_reference(self, tmp_path: Path):
        """Env-var name references like sk-OPENAI_API_KEY_HERE must not be flagged (no digit)."""
        line = 'key = "sk-OPENAI_API_KEY_HERE_PLEASE"\n'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"Env-var name references should not be flagged; got: {findings}"

    def test_does_not_flag_url_slug_with_uppercase(self, tmp_path: Path):
        """URL slugs with no digits like sk-SOME-WORDS-ABOUT-MODELS must not be flagged."""
        line = 'url = "sk-THE-MODEL-TO-ADOPT-A-PERSONA-HERE"\n'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], f"URL slug without digits should not be flagged; got: {findings}"

    def test_does_not_flag_sk_inside_word(self, tmp_path: Path):
        """'sk-' embedded inside a longer word (e.g. 'ask-gpt-4-1-...') must not be flagged.

        Regression test: Markdown anchor slugs like '#step-3-ask-gpt-4-1-to-critique'
        contain the substring 'sk-gpt-4-1-...' (hidden inside 'ask-').  The
        negative lookbehind (?<![A-Za-z0-9]) prevents this from matching.
        """
        # Simulates the anchor href from the Prompt_migration_guide.ipynb TOC.
        line = 'url = "#step-3-ask-gpt-4-1-to-critique-the-prompt"\n'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], (
            f"'sk-' inside a word like 'ask-' should not be flagged; got: {findings}"
        )

    def test_still_flags_real_key_with_digits(self, tmp_path: Path):
        """Real OpenAI keys that contain digits must still be detected."""
        line = 'key = "sk-proj-AbCdEf123456789abcdefghij"\n'
        findings = check_sensitive_info(tmp_path / "vuln.py", line)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"


# ---------------------------------------------------------------------------
# LLM05 AST tests
# ---------------------------------------------------------------------------


class TestASTLLM05ImproperOutput:
    """AST-layer tests for LLM05: Improper Output Handling."""

    def _analyze(self, tmp_path: Path, code: str, strict: bool = False) -> dict:
        from llmarmor.ast_analysis import analyze
        return analyze(str(tmp_path / "app.py"), code, strict=strict)

    def test_eval_tainted_variable_flagged_critical(self, tmp_path: Path):
        """eval(user_input) where user_input is tainted must produce LLM05 CRITICAL."""
        code = """\
def process(user_input):
    result = eval(user_input)
    return result
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, f"Expected LLM05 finding for eval(user_input); got: {result['findings']}"
        assert any(f["severity"] == "CRITICAL" for f in llm05), (
            f"eval(tainted) must be CRITICAL; got: {[f['severity'] for f in llm05]}"
        )

    def test_exec_tainted_variable_flagged_critical(self, tmp_path: Path):
        """exec(data) where data is tainted must produce LLM05 CRITICAL."""
        code = """\
data = request.json["cmd"]
exec(data)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, f"Expected LLM05 for exec(tainted); got: {result['findings']}"
        assert any(f["severity"] == "CRITICAL" for f in llm05), (
            f"exec(tainted) must be CRITICAL; got: {[f['severity'] for f in llm05]}"
        )

    def test_subprocess_run_tainted_flagged_critical(self, tmp_path: Path):
        """subprocess.run(data) where data is tainted must produce LLM05 CRITICAL."""
        code = """\
import subprocess
data = request.json["cmd"]
subprocess.run(data, shell=True)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, f"Expected LLM05 for subprocess.run(tainted); got: {result['findings']}"
        assert any(f["severity"] == "CRITICAL" for f in llm05), (
            f"subprocess.run(tainted) must be CRITICAL; got: {[f['severity'] for f in llm05]}"
        )

    def test_markup_tainted_flagged_high(self, tmp_path: Path):
        """Markup(text) where text is a function parameter must produce LLM05 HIGH."""
        code = """\
def render(text):
    from markupsafe import Markup
    return Markup(text)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, f"Expected LLM05 for Markup(tainted); got: {result['findings']}"
        assert any(f["severity"] == "HIGH" for f in llm05), (
            f"Markup(tainted) must be HIGH; got: {[f['severity'] for f in llm05]}"
        )

    def test_json_loads_tainted_info_in_normal_mode(self, tmp_path: Path):
        """json.loads(content) where content is tainted must produce LLM05 INFO in normal mode."""
        code = """\
import json
def process(content):
    data = json.loads(content)
    return data
"""
        result = self._analyze(tmp_path, code, strict=False)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, f"Expected LLM05 for json.loads(tainted); got: {result['findings']}"
        assert any(f["severity"] == "INFO" for f in llm05), (
            f"json.loads(tainted) must be INFO in normal mode; got: {[f['severity'] for f in llm05]}"
        )

    def test_json_loads_tainted_medium_in_strict_mode(self, tmp_path: Path):
        """json.loads(content) where content is tainted must produce LLM05 MEDIUM in strict mode."""
        code = """\
import json
def process(content):
    data = json.loads(content)
    return data
"""
        result = self._analyze(tmp_path, code, strict=True)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, f"Expected LLM05 for json.loads(tainted) in strict; got: {result['findings']}"
        assert any(f["severity"] == "MEDIUM" for f in llm05), (
            f"json.loads(tainted) must be MEDIUM in strict mode; got: {[f['severity'] for f in llm05]}"
        )

    def test_eval_tainted_clears_regex_line(self, tmp_path: Path):
        """AST LLM05 finding must add (line, 'LLM05') to cleared to suppress regex duplicate."""
        code = """\
def process(user_input):
    result = eval(user_input)
    return result
"""
        result = self._analyze(tmp_path, code)
        llm05_findings = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05_findings, "Expected at least one LLM05 finding"
        for f in llm05_findings:
            assert (f["line"], "LLM05") in result["cleared"], (
                f"AST LLM05 finding on line {f['line']} should be in cleared set"
            )

    def test_safe_eval_call_not_tainted_not_flagged(self, tmp_path: Path):
        """eval(literal_expr) where expr is a string literal must NOT produce LLM05."""
        code = 'result = eval("1 + 2")\n'
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert not llm05, (
            f"eval() with string literal should not produce LLM05; got: {llm05}"
        )


# ---------------------------------------------------------------------------
# LLM08 AST tests
# ---------------------------------------------------------------------------


class TestASTLLM08ExcessiveAgency:
    """AST-layer tests for LLM08: Excessive Agency."""

    def _analyze(self, tmp_path: Path, code: str, strict: bool = False) -> dict:
        from llmarmor.ast_analysis import analyze
        return analyze(str(tmp_path / "app.py"), code, strict=strict)

    def test_getattr_tainted_name_flagged_critical(self, tmp_path: Path):
        """getattr(module, name)(args) where name is tainted must produce LLM08 CRITICAL."""
        code = """\
def dispatch(module, name, args):
    return getattr(module, name)(args)
"""
        result = self._analyze(tmp_path, code)
        llm08 = [f for f in result["findings"] if f["rule_id"] == "LLM08"]
        assert llm08, (
            f"Expected LLM08 for getattr(module, tainted_name)(); got: {result['findings']}"
        )
        assert any(f["severity"] == "CRITICAL" for f in llm08), (
            f"getattr(module, tainted_name)() must be CRITICAL; got: {[f['severity'] for f in llm08]}"
        )

    def test_getattr_tainted_clears_regex_line(self, tmp_path: Path):
        """AST LLM08 finding must add (line, 'LLM08') to cleared."""
        code = """\
def dispatch(module, name, args):
    return getattr(module, name)(args)
"""
        result = self._analyze(tmp_path, code)
        llm08_findings = [f for f in result["findings"] if f["rule_id"] == "LLM08"]
        assert llm08_findings, "Expected at least one LLM08 finding"
        for f in llm08_findings:
            assert (f["line"], "LLM08") in result["cleared"], (
                f"AST LLM08 finding on line {f['line']} should be in cleared set"
            )

    def test_globals_tainted_dispatch_flagged_critical(self, tmp_path: Path):
        """globals()[tainted_name]() must produce LLM08 CRITICAL."""
        code = """\
def execute(fn_name):
    return globals()[fn_name]()
"""
        result = self._analyze(tmp_path, code)
        llm08 = [f for f in result["findings"] if f["rule_id"] == "LLM08"]
        assert llm08, (
            f"Expected LLM08 for globals()[tainted_name](); got: {result['findings']}"
        )
        assert any(f["severity"] == "CRITICAL" for f in llm08), (
            f"globals()[tainted_name]() must be CRITICAL; got: {[f['severity'] for f in llm08]}"
        )

    def test_getattr_with_string_literal_not_flagged(self, tmp_path: Path):
        """getattr(obj, 'fixed_method')() must NOT produce LLM08 (safe static dispatch)."""
        code = 'result = getattr(obj, "fixed_method")()\n'
        result = self._analyze(tmp_path, code)
        llm08 = [f for f in result["findings"] if f["rule_id"] == "LLM08"]
        assert not llm08, (
            f"getattr with string literal must not be flagged; got: {llm08}"
        )

    def test_getattr_string_literal_clears_regex_line(self, tmp_path: Path):
        """getattr(obj, "name") with string literal must add line to cleared (regex suppression)."""
        code = 'result = getattr(obj, "method_name")\n'
        result = self._analyze(tmp_path, code)
        assert (1, "LLM08") in result["cleared"], (
            "getattr with string literal should add line to cleared to suppress regex; "
            f"cleared={result['cleared']}"
        )


# ---------------------------------------------------------------------------
# Tests for eval/test context downgrade (LLM05 and LLM08)
# ---------------------------------------------------------------------------


class TestEvalContextDowngrade:
    """Tests that LLM05 and LLM08 findings are downgraded to INFO in test/eval files."""

    def _analyze(self, filepath: str, code: str) -> dict:
        from llmarmor.ast_analysis import analyze
        return analyze(filepath, code)

    def _scan(self, py_file: Path, code: str) -> list[dict]:
        from llmarmor.scanner import _scan_file
        findings: list[dict] = []
        _scan_file(py_file, code, findings)
        return findings

    def test_ast_llm05_downgraded_in_test_file(self, tmp_path: Path):
        """LLM05 AST findings in a test file must be downgraded to INFO."""
        test_file = tmp_path / "tests" / "test_app.py"
        test_file.parent.mkdir()
        code = """\
def test_something(user_input):
    eval(user_input)
"""
        result = self._analyze(str(test_file), code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, "Expected LLM05 finding in test file"
        assert all(f["severity"] == "INFO" for f in llm05), (
            f"LLM05 findings in test file must be INFO; got: {[f['severity'] for f in llm05]}"
        )
        assert all("[eval context]" in f["description"] for f in llm05), (
            "LLM05 descriptions in test file must be prefixed with [eval context]"
        )

    def test_ast_llm08_downgraded_in_test_file(self, tmp_path: Path):
        """LLM08 AST findings in a test file must be downgraded to INFO."""
        test_file = tmp_path / "tests" / "test_app.py"
        test_file.parent.mkdir()
        code = """\
def test_dispatch(module, name):
    return getattr(module, name)()
"""
        result = self._analyze(str(test_file), code)
        llm08 = [f for f in result["findings"] if f["rule_id"] == "LLM08"]
        assert llm08, "Expected LLM08 finding in test file"
        assert all(f["severity"] == "INFO" for f in llm08), (
            f"LLM08 findings in test file must be INFO; got: {[f['severity'] for f in llm08]}"
        )

    def test_regex_llm05_downgraded_in_test_file(self, tmp_path: Path):
        """LLM05 regex findings in a test file must be downgraded to INFO by scanner."""
        test_file = tmp_path / "tests" / "test_something.py"
        test_file.parent.mkdir()
        code = "subprocess.Popen(llm_output)\n"
        findings = self._scan(test_file, code)
        llm05 = [f for f in findings if f["rule_id"] == "LLM05"]
        assert llm05, "Expected LLM05 finding for subprocess.Popen(llm_output) in test file"
        assert all(f["severity"] == "INFO" for f in llm05), (
            f"LLM05 regex findings in test file must be INFO; got: {[f['severity'] for f in llm05]}"
        )

    def test_regex_llm08_downgraded_in_test_file(self, tmp_path: Path):
        """LLM08 regex findings in a test file must be downgraded to INFO by scanner."""
        test_file = tmp_path / "tests" / "test_agent.py"
        test_file.parent.mkdir()
        code = "tools = [CodeInterpreterTool()]\n"
        findings = self._scan(test_file, code)
        llm08 = [f for f in findings if f["rule_id"] == "LLM08"]
        assert llm08, "Expected LLM08 finding for CodeInterpreterTool() in test file"
        assert all(f["severity"] == "INFO" for f in llm08), (
            f"LLM08 regex findings in test file must be INFO; got: {[f['severity'] for f in llm08]}"
        )

    def test_analyze_returns_is_eval_context_flag(self, tmp_path: Path):
        """analyze() must return is_eval_context=True for files in a tests/ directory."""
        test_file = tmp_path / "tests" / "test_utils.py"
        test_file.parent.mkdir()
        result = self._analyze(str(test_file), "x = 1\n")
        assert result.get("is_eval_context") is True, (
            f"Expected is_eval_context=True for file in tests/ dir; got: {result.get('is_eval_context')}"
        )

    def test_analyze_returns_is_eval_context_false_for_production(self, tmp_path: Path):
        """analyze() must return is_eval_context=False for production code files."""
        prod_file = tmp_path / "app.py"
        result = self._analyze(str(prod_file), "x = 1\n")
        assert result.get("is_eval_context") is False, (
            f"Expected is_eval_context=False for production file; got: {result.get('is_eval_context')}"
        )

    def test_llm05_not_downgraded_in_production_file(self, tmp_path: Path):
        """LLM05 findings in production files must retain their original severity."""
        code = """\
def process(user_input):
    eval(user_input)
"""
        result = self._analyze(str(tmp_path / "app.py"), code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, "Expected LLM05 finding"
        assert all(f["severity"] == "CRITICAL" for f in llm05), (
            f"LLM05 findings in production files must be CRITICAL; got: {[f['severity'] for f in llm05]}"
        )


# ---------------------------------------------------------------------------
# Tests for LLM05 subprocess LLM-context awareness
# ---------------------------------------------------------------------------


class TestSubprocessSourceTaint:
    """Tests that LLM05 shell-sink AST checks use source-taint (not function-param taint)."""

    def _analyze(self, tmp_path: Path, code: str) -> dict:
        from llmarmor.ast_analysis import analyze
        return analyze(str(tmp_path / "app.py"), code)

    def test_subprocess_with_function_param_not_flagged(self, tmp_path: Path):
        """subprocess.Popen(cmd) where cmd is a plain function parameter must NOT be flagged.

        This is the scheduler.py / utility-function false positive case.
        """
        code = """\
import subprocess

def run_job(command, interval):
    subprocess.Popen(command)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert not llm05, (
            f"subprocess.Popen(function_param) must NOT produce LLM05 (false positive); got: {llm05}"
        )

    def test_subprocess_with_request_data_flagged(self, tmp_path: Path):
        """subprocess.run(data) where data comes from request.json must be flagged."""
        code = """\
import subprocess
data = request.json["cmd"]
subprocess.run(data, shell=True)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, (
            f"subprocess.run(request.json data) must produce LLM05; got: {result['findings']}"
        )
        assert any(f["severity"] == "CRITICAL" for f in llm05)

    def test_subprocess_with_llm_api_response_flagged(self, tmp_path: Path):
        """subprocess.run(content) where content comes from an LLM API call must be flagged."""
        code = """\
import subprocess
response = client.chat.completions.create(model="gpt-4", messages=[])
content = response.choices[0].message.content
subprocess.run(content, shell=True)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, (
            f"subprocess.run(llm_api_response) must produce LLM05; got: {result['findings']}"
        )
        assert any(f["severity"] == "CRITICAL" for f in llm05)

    def test_subprocess_with_stdin_input_flagged(self, tmp_path: Path):
        """subprocess.run(cmd) where cmd comes from input() must be flagged."""
        code = """\
import subprocess
cmd = input("Enter command: ")
subprocess.run(cmd, shell=True)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05, (
            f"subprocess.run(input()) must produce LLM05; got: {result['findings']}"
        )

    def test_subprocess_with_alias_of_param_not_flagged(self, tmp_path: Path):
        """subprocess.Popen(alias) where alias = param must NOT be flagged."""
        code = """\
import subprocess

def run_command(cmd):
    command = cmd
    subprocess.Popen(command)
"""
        result = self._analyze(tmp_path, code)
        llm05 = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert not llm05, (
            f"subprocess.Popen(alias of param) must NOT produce LLM05; got: {llm05}"
        )


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


# ---------------------------------------------------------------------------
# Tests for new features: strict mode, formatters, path truncation
# ---------------------------------------------------------------------------


class TestStrictMode:
    """Tests for strict mode (--strict flag) behavior."""

    def _analyze_strict(self, tmp_path: Path, code: str) -> dict:
        from llmarmor.ast_analysis import analyze
        py_file = tmp_path / "test_strict.py"
        py_file.write_text(code)
        return analyze(str(py_file), code, strict=True)

    def _analyze_normal(self, tmp_path: Path, code: str) -> dict:
        from llmarmor.ast_analysis import analyze
        py_file = tmp_path / "test_normal.py"
        py_file.write_text(code)
        return analyze(str(py_file), code, strict=False)

    # ------------------------------------------------------------------
    # Strict mode: plain tainted variable in system role
    # ------------------------------------------------------------------

    def test_strict_system_role_plain_tainted_var_flagged(self, tmp_path: Path):
        """In strict mode, plain tainted variable as system content must be flagged."""
        code = """\
def handle(system, user):
    msg = {"role": "system", "content": system}
    return msg
"""
        result = self._analyze_strict(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Strict mode: plain tainted variable as system content should be flagged; "
            f"got: {result['findings']}"
        )

    def test_normal_system_role_plain_tainted_var_not_flagged(self, tmp_path: Path):
        """In normal mode, plain tainted variable as system content must only produce INFO (hidden by default)."""
        code = """\
def handle(system, user):
    msg = {"role": "system", "content": system}
    return msg
"""
        result = self._analyze_normal(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert all(f["severity"] == "INFO" for f in llm01), (
            "Normal mode: plain tainted variable as system content should only produce INFO-level LLM01; "
            f"got: {result['findings']}"
        )

    def test_strict_system_role_plain_var_is_medium_severity(self, tmp_path: Path):
        """In strict mode, plain tainted var in system role must be MEDIUM severity."""
        code = """\
def handle(system):
    msg = {"role": "system", "content": system}
    return msg
"""
        result = self._analyze_strict(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected LLM01 finding in strict mode"
        assert llm01[0]["severity"] == "MEDIUM", (
            f"Expected MEDIUM severity in strict mode; got: {llm01[0]['severity']}"
        )

    def test_strict_user_role_plain_tainted_var_flagged(self, tmp_path: Path):
        """In strict mode, plain tainted variable as user content must be flagged."""
        code = """\
def handle(user):
    msg = {"role": "user", "content": user}
    return msg
"""
        result = self._analyze_strict(tmp_path, code)
        assert any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Strict mode: plain tainted variable as user content should be flagged; "
            f"got: {result['findings']}"
        )

    def test_normal_user_role_plain_tainted_var_not_flagged(self, tmp_path: Path):
        """In normal mode, plain tainted variable as user content must only produce INFO (hidden by default)."""
        code = """\
def handle(user):
    msg = {"role": "user", "content": user}
    return msg
"""
        result = self._analyze_normal(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert all(f["severity"] == "INFO" for f in llm01), (
            "Normal mode: plain tainted variable as user content should only produce INFO-level LLM01; "
            f"got: {result['findings']}"
        )

    def test_strict_user_role_plain_var_message_mentions_sanitization(self, tmp_path: Path):
        """In strict mode, user-role plain-var finding should mention sanitization."""
        code = """\
def handle(user):
    msg = {"role": "user", "content": user}
    return msg
"""
        result = self._analyze_strict(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected LLM01 finding in strict mode"
        desc_lower = llm01[0]["description"].lower()
        assert "sanitization" in desc_lower or "validation" in desc_lower, (
            f"User-role strict mode description should mention sanitization/validation; "
            f"got: {llm01[0]['description']}"
        )

    # ------------------------------------------------------------------
    # Strict mode: LLM07 hardcoded system prompt messaging
    # ------------------------------------------------------------------

    def test_strict_llm07_is_medium_severity(self, tmp_path: Path):
        """In strict mode, hardcoded system prompt must be MEDIUM severity."""
        from llmarmor.rules.llm07_system_prompt_leak import check_system_prompt_leak
        code = (
            'SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. '
            'You have access to customer databases and can process refunds up to $500."'
        )
        findings = check_system_prompt_leak(tmp_path / "vuln.py", code, strict=True)
        assert findings, "Expected LLM07 finding in strict mode"
        assert findings[0]["severity"] == "MEDIUM", (
            f"Strict mode LLM07 should be MEDIUM; got: {findings[0]['severity']}"
        )

    def test_normal_llm07_is_info_severity(self, tmp_path: Path):
        """In normal mode, hardcoded system prompt must remain INFO severity."""
        from llmarmor.rules.llm07_system_prompt_leak import check_system_prompt_leak
        code = (
            'SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. '
            'You have access to customer databases and can process refunds up to $500."'
        )
        findings = check_system_prompt_leak(tmp_path / "vuln.py", code, strict=False)
        assert findings, "Expected LLM07 finding in normal mode"
        assert findings[0]["severity"] == "INFO", (
            f"Normal mode LLM07 should be INFO; got: {findings[0]['severity']}"
        )

    def test_strict_llm07_message_mentions_exposure(self, tmp_path: Path):
        """In strict mode, LLM07 description must mention exposure/published code."""
        from llmarmor.rules.llm07_system_prompt_leak import check_system_prompt_leak
        code = (
            'SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. '
            'You have access to customer databases and can process refunds up to $500."'
        )
        findings = check_system_prompt_leak(tmp_path / "vuln.py", code, strict=True)
        assert findings, "Expected LLM07 finding"
        desc = findings[0]["description"].lower()
        assert "published" in desc or "open source" in desc or "visible" in desc, (
            f"Strict mode LLM07 description should mention publication/visibility; "
            f"got: {findings[0]['description']}"
        )

    def test_strict_run_scan_passes_strict_through(self, tmp_path: Path):
        """run_scan(strict=True) must produce MEDIUM LLM07 findings."""
        code = (
            'SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. '
            'You have access to customer databases and can process refunds up to $500."\n'
        )
        py_file = tmp_path / "app.py"
        py_file.write_text(code)
        findings = run_scan(str(tmp_path), strict=True)
        llm07 = [f for f in findings if f["rule_id"] == "LLM07"]
        assert llm07, f"Expected LLM07 in strict scan; got: {findings}"
        assert llm07[0]["severity"] == "MEDIUM", (
            f"strict run_scan LLM07 should be MEDIUM; got: {llm07[0]['severity']}"
        )

    # ------------------------------------------------------------------
    # Strict mode: f-string injection still works normally
    # ------------------------------------------------------------------

    def test_strict_fstring_injection_still_flagged_critical(self, tmp_path: Path):
        """F-string tainted injection in system role must remain CRITICAL in strict mode."""
        code = """\
def handle(user_input):
    msg = {"role": "system", "content": f"Help: {user_input}"}
    return msg
"""
        result = self._analyze_strict(tmp_path, code)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected LLM01 finding for f-string in strict mode"
        assert llm01[0]["severity"] == "CRITICAL", (
            f"F-string injection should still be CRITICAL in strict mode; "
            f"got: {llm01[0]['severity']}"
        )


class TestFormatters:
    """Tests for output formatters (grouped, flat, json, markdown)."""

    _SAMPLE_FINDINGS = [
        {
            "rule_id": "LLM01",
            "rule_name": "Prompt Injection",
            "severity": "CRITICAL",
            "filepath": "app/chat.py",
            "line": 42,
            "description": "User input is interpolated into system role.",
            "fix_suggestion": "Pass user input as a separate 'role: user' message.",
        },
        {
            "rule_id": "LLM10",
            "rule_name": "Unbounded Consumption",
            "severity": "MEDIUM",
            "filepath": "app/chat.py",
            "line": 75,
            "description": "LLM API call without max_tokens.",
            "fix_suggestion": "Set max_tokens on LLM API calls.",
        },
        {
            "rule_id": "LLM10",
            "rule_name": "Unbounded Consumption",
            "severity": "MEDIUM",
            "filepath": "api/handler.py",
            "line": 30,
            "description": "LLM API call without max_tokens.",
            "fix_suggestion": "Set max_tokens on LLM API calls.",
        },
    ]

    def _make_console(self):
        from io import StringIO
        from rich.console import Console
        return Console(file=StringIO(), width=120)

    def _get_output(self, console) -> str:
        return console.file.getvalue()

    # ------------------------------------------------------------------
    # JSON format
    # ------------------------------------------------------------------

    def test_json_output_is_valid_json(self, capsys):
        """json format must produce valid JSON with meta and findings blocks."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_json
        console = Console(file=StringIO(), width=120)
        format_json(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        parsed = _json.loads(captured.out)
        assert isinstance(parsed, dict), f"JSON output should be a dict; got: {type(parsed)}"
        assert "meta" in parsed, "JSON output should have a 'meta' key"
        assert "findings" in parsed, "JSON output should have a 'findings' key"
        # 3 flat findings → 2 groups (LLM01 × 1 location, LLM10 × 2 locations)
        assert len(parsed["findings"]) == 2, (
            f"Expected 2 grouped findings in JSON; got: {len(parsed['findings'])}"
        )

    def test_json_output_has_required_keys(self, capsys):
        """Each grouped JSON finding must have the new required keys."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_json
        console = Console(file=StringIO(), width=120)
        format_json(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        parsed = _json.loads(captured.out)
        required_keys = {"rule_id", "rule_name", "severity", "description", "fix_suggestion", "locations"}
        for finding in parsed["findings"]:
            missing = required_keys - finding.keys()
            assert not missing, f"JSON finding missing keys: {missing}"
            assert isinstance(finding["locations"], list), "locations must be a list"
            for loc in finding["locations"]:
                assert "filepath" in loc and "line" in loc, f"Location missing keys: {loc}"

    def test_json_output_meta_block(self, capsys):
        """JSON output must contain a valid meta block with summary counts."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_json
        console = Console(file=StringIO(), width=120)
        format_json(self._SAMPLE_FINDINGS, console, "/my/project", mode="strict")
        captured = capsys.readouterr()
        parsed = _json.loads(captured.out)
        meta = parsed["meta"]
        assert meta["tool"] == "llmarmor"
        assert meta["scanned_path"] == "/my/project"
        assert meta["mode"] == "strict"
        assert "timestamp" in meta
        summary = meta["summary"]
        assert summary["total"] == 3
        assert summary["critical"] == 1
        assert summary["medium"] == 2

    # ------------------------------------------------------------------
    # Markdown format
    # ------------------------------------------------------------------

    def test_markdown_output_has_header(self, capsys):
        """Markdown output must start with '# LLM Armor Scan Report'."""
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_markdown
        console = Console(file=StringIO(), width=120)
        format_markdown(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        assert "# LLM Armor Scan Report" in captured.out, (
            f"Markdown output should start with H1; got: {captured.out[:200]}"
        )

    def test_markdown_output_has_rule_sections(self, capsys):
        """Markdown output must contain H2 sections for each rule."""
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_markdown
        console = Console(file=StringIO(), width=120)
        format_markdown(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        assert "## LLM01" in captured.out, "Markdown should have LLM01 section"
        assert "## LLM10" in captured.out, "Markdown should have LLM10 section"

    def test_markdown_output_has_table(self, capsys):
        """Markdown output must contain a table with File and Line columns."""
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_markdown
        console = Console(file=StringIO(), width=120)
        format_markdown(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        assert "| File | Line |" in captured.out, (
            f"Markdown should contain a table header; got: {captured.out[:500]}"
        )

    def test_markdown_output_has_scanned_path(self, capsys):
        """Markdown output must include the scanned path."""
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_markdown
        console = Console(file=StringIO(), width=120)
        format_markdown(self._SAMPLE_FINDINGS, console, "/my/project")
        captured = capsys.readouterr()
        assert "/my/project" in captured.out, (
            "Markdown output should include the scanned path"
        )

    # ------------------------------------------------------------------
    # Grouped format
    # ------------------------------------------------------------------

    def test_grouped_output_groups_by_rule(self):
        """Grouped format must show each rule_id as a section header."""
        from llmarmor.formatters import format_grouped
        console = self._make_console()
        format_grouped(self._SAMPLE_FINDINGS, console, "/some/path")
        output = self._get_output(console)
        assert "LLM01" in output, "Grouped output should show LLM01 section"
        assert "LLM10" in output, "Grouped output should show LLM10 section"

    def test_grouped_output_shows_all_locations(self):
        """Grouped format must list all file:line references per rule."""
        from llmarmor.formatters import format_grouped
        console = self._make_console()
        format_grouped(self._SAMPLE_FINDINGS, console, "/some/path")
        output = self._get_output(console)
        assert "42" in output, "Grouped output should show line 42"
        assert "75" in output, "Grouped output should show line 75"
        assert "30" in output, "Grouped output should show line 30"

    def test_grouped_output_shows_summary(self):
        """Grouped format must include a summary line."""
        from llmarmor.formatters import format_grouped
        console = self._make_console()
        format_grouped(self._SAMPLE_FINDINGS, console, "/some/path")
        output = self._get_output(console)
        assert "Summary" in output, "Grouped output should include Summary"
        assert "3" in output, "Summary should mention 3 findings"

    def test_grouped_output_no_findings(self):
        """Grouped format with no findings must show 'No vulnerabilities detected'."""
        from llmarmor.formatters import format_grouped
        console = self._make_console()
        format_grouped([], console, "/some/path")
        output = self._get_output(console)
        assert "No vulnerabilities detected" in output

    # ------------------------------------------------------------------
    # Flat format
    # ------------------------------------------------------------------

    def test_flat_output_shows_findings(self):
        """Flat format must show each finding."""
        from llmarmor.formatters import format_flat
        console = self._make_console()
        format_flat(self._SAMPLE_FINDINGS, console, "/some/path")
        output = self._get_output(console)
        assert "LLM01" in output
        assert "LLM10" in output

    def test_flat_output_no_findings(self):
        """Flat format with no findings must show 'No vulnerabilities detected'."""
        from llmarmor.formatters import format_flat
        console = self._make_console()
        format_flat([], console, "/some/path")
        output = self._get_output(console)
        assert "No vulnerabilities detected" in output

    # ------------------------------------------------------------------
    # render() dispatcher
    # ------------------------------------------------------------------

    def test_render_unknown_format_raises(self):
        """render() must raise ValueError for unknown format."""
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import render
        console = Console(file=StringIO(), width=120)
        with pytest.raises(ValueError, match="Unknown format"):
            render(self._SAMPLE_FINDINGS, fmt="xls", console=console, scan_path="/p")

    def test_render_verbose_false_default(self):
        """render() verbose parameter defaults to False (INFO hidden)."""
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import render
        console = Console(file=StringIO(), width=120)
        info_finding = {
            "rule_id": "LLM07", "rule_name": "System Prompt Leakage",
            "severity": "INFO", "filepath": "a.py", "line": 1,
            "description": "Some info.", "fix_suggestion": "",
        }
        render([info_finding], fmt="grouped", console=console, scan_path="/p")
        assert "LLM07" not in console.file.getvalue(), (
            "INFO finding should be hidden by default (verbose=False)"
        )


class TestBuildMode:
    """Tests for the _build_mode helper in cli.py."""

    def test_normal_mode(self):
        from llmarmor.cli import _build_mode
        assert _build_mode(strict=False, verbose=False) == "normal"

    def test_strict_mode(self):
        from llmarmor.cli import _build_mode
        assert _build_mode(strict=True, verbose=False) == "strict"

    def test_verbose_mode(self):
        from llmarmor.cli import _build_mode
        assert _build_mode(strict=False, verbose=True) == "verbose"

    def test_strict_verbose_mode(self):
        from llmarmor.cli import _build_mode
        assert _build_mode(strict=True, verbose=True) == "strict+verbose"


    """Tests for the path truncation helper."""

    def test_short_path_not_truncated(self):
        """Paths shorter than max_width must be returned unchanged."""
        from llmarmor.formatters import truncate_path
        path = "src/app.py"
        assert truncate_path(path, max_width=80) == path

    def test_long_path_truncated_from_middle(self):
        """Paths longer than max_width must have middle truncated."""
        from llmarmor.formatters import truncate_path
        path = "src/very/long/deeply/nested/directory/structure/handlers/chat.py"
        result = truncate_path(path, max_width=40)
        assert len(result) <= 40, f"Result should be ≤40 chars; got {len(result)}: {result!r}"
        assert result.endswith("chat.py"), f"Result should end with filename; got: {result!r}"
        assert "..." in result, f"Result should contain ellipsis; got: {result!r}"

    def test_truncated_path_length_respected(self):
        """Truncated path must not exceed max_width."""
        from llmarmor.formatters import truncate_path
        path = "a" * 100 + "/b" * 50 + "/file.py"
        result = truncate_path(path, max_width=50)
        assert len(result) <= 50, f"Truncated path too long: {len(result)}: {result!r}"

    def test_truncated_path_preserves_filename(self):
        """Truncated path must always end with the original filename."""
        from llmarmor.formatters import truncate_path
        path = "/home/user/projects/my-very-long-project-name/src/deep/nested/module.py"
        result = truncate_path(path, max_width=40)
        assert result.endswith("module.py"), f"Filename must be preserved; got: {result!r}"


# ---------------------------------------------------------------------------
# Tests for verbose flag
# ---------------------------------------------------------------------------


class TestVerboseFlag:
    """Tests for --verbose / -v flag behaviour."""

    _INFO_FINDING = {
        "rule_id": "LLM07",
        "rule_name": "System Prompt Leakage",
        "severity": "INFO",
        "filepath": "app/chat.py",
        "line": 10,
        "description": "System prompt is hardcoded.",
        "fix_suggestion": "Use env vars.",
    }
    _LOW_FINDING = {
        "rule_id": "LLM01",
        "rule_name": "Prompt Injection",
        "severity": "LOW",
        "filepath": "app/chat.py",
        "line": 20,
        "description": "Low risk finding.",
        "fix_suggestion": "Sanitize inputs.",
    }
    _CRITICAL_FINDING = {
        "rule_id": "LLM02",
        "rule_name": "Sensitive Information Disclosure",
        "severity": "CRITICAL",
        "filepath": "app/chat.py",
        "line": 30,
        "description": "Hardcoded API key.",
        "fix_suggestion": "Use env vars.",
    }

    def _make_console(self):
        from io import StringIO
        from rich.console import Console
        return Console(file=StringIO(), width=120)

    def test_verbose_false_hides_info_in_grouped(self):
        """Without --verbose, INFO findings must not appear in grouped output."""
        from llmarmor.formatters import render
        console = self._make_console()
        findings = [self._INFO_FINDING, self._CRITICAL_FINDING]
        render(findings, fmt="grouped", console=console, scan_path="/p", verbose=False)
        output = console.file.getvalue()
        assert "LLM02" in output, "CRITICAL finding should be shown"
        # INFO is filtered — the LLM07 rule section should not appear
        assert "LLM07" not in output, "INFO finding should be hidden in non-verbose mode"

    def test_verbose_true_shows_info_in_grouped(self):
        """With --verbose, INFO findings must appear in grouped output."""
        from llmarmor.formatters import render
        console = self._make_console()
        findings = [self._INFO_FINDING, self._CRITICAL_FINDING]
        render(findings, fmt="grouped", console=console, scan_path="/p", verbose=True)
        output = console.file.getvalue()
        assert "LLM07" in output, "INFO finding should be shown in verbose mode"
        assert "LLM02" in output, "CRITICAL finding should still be shown"

    def test_verbose_false_hides_low_in_grouped(self):
        """Without --verbose, LOW findings must not appear in grouped output."""
        from llmarmor.formatters import render
        console = self._make_console()
        render(
            [self._LOW_FINDING, self._CRITICAL_FINDING],
            fmt="grouped",
            console=console,
            scan_path="/p",
            verbose=False,
        )
        output = console.file.getvalue()
        # LLM01 appears only as LOW; CRITICAL is LLM02
        assert "LLM02" in output
        # LOW finding rule section should not appear (its only finding is LOW severity)
        assert "LLM01" not in output, "LOW finding (LLM01) should be hidden in non-verbose mode"

    def test_verbose_true_shows_low_in_grouped(self):
        """With --verbose, LOW findings must appear in grouped output."""
        from llmarmor.formatters import render
        console = self._make_console()
        render(
            [self._LOW_FINDING, self._CRITICAL_FINDING],
            fmt="grouped",
            console=console,
            scan_path="/p",
            verbose=True,
        )
        output = console.file.getvalue()
        assert "LLM01" in output, "LOW finding (LLM01) should be shown in verbose mode"

    def test_verbose_false_hides_info_in_json(self, capsys):
        """Without --verbose, INFO findings must not appear in JSON output."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import render
        console = Console(file=StringIO(), width=120)
        render(
            [self._INFO_FINDING, self._CRITICAL_FINDING],
            fmt="json",
            console=console,
            scan_path="/p",
            verbose=False,
        )
        parsed = _json.loads(capsys.readouterr().out)
        severities = {g["severity"] for g in parsed["findings"]}
        assert "INFO" not in severities, "INFO should be filtered from JSON in non-verbose mode"
        assert "CRITICAL" in severities, "CRITICAL should remain in JSON"

    def test_verbose_true_shows_info_in_json(self, capsys):
        """With --verbose, INFO findings must appear in JSON output."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import render
        console = Console(file=StringIO(), width=120)
        render(
            [self._INFO_FINDING, self._CRITICAL_FINDING],
            fmt="json",
            console=console,
            scan_path="/p",
            verbose=True,
        )
        parsed = _json.loads(capsys.readouterr().out)
        severities = {g["severity"] for g in parsed["findings"]}
        assert "INFO" in severities, "INFO should appear in JSON in verbose mode"


# ---------------------------------------------------------------------------
# Tests for the rule registry
# ---------------------------------------------------------------------------


class TestRegistry:
    """Tests for the rule registry (registry.py)."""

    def test_get_known_rule(self):
        """registry.get() must return the correct RuleDefinition."""
        from llmarmor.registry import registry
        rule = registry.get("LLM01")
        assert rule.rule_id == "LLM01"
        assert rule.name == "Prompt Injection"

    def test_get_unknown_rule_raises(self):
        """registry.get() must raise KeyError for an unknown rule."""
        from llmarmor.registry import registry
        with pytest.raises(KeyError):
            registry.get("LLM99")

    def test_active_rules_returns_only_active(self):
        """active_rules() must only return ACTIVE rules."""
        from llmarmor.registry import registry, Status
        active = registry.active_rules()
        assert len(active) == 7, f"Expected 7 active rules; got {len(active)}"
        for r in active:
            assert r.status == Status.ACTIVE, f"{r.rule_id} should be ACTIVE"

    def test_active_rule_ids(self):
        """active_rules() must include LLM01, LLM02, LLM05, LLM06, LLM07, LLM08, LLM10."""
        from llmarmor.registry import registry
        ids = {r.rule_id for r in registry.active_rules()}
        assert ids == {"LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM08", "LLM10"}

    def test_all_rules_count(self):
        """all_rules() must return all 10 OWASP LLM rules."""
        from llmarmor.registry import registry
        assert len(registry.all_rules()) == 10

    def test_by_status_planned(self):
        """by_status(PLANNED) must return no rules (LLM05 and LLM08 are now ACTIVE)."""
        from llmarmor.registry import registry, Status
        planned = {r.rule_id for r in registry.by_status(Status.PLANNED)}
        assert planned == set()

    def test_by_status_out_of_scope(self):
        """by_status(OUT_OF_SCOPE) must return LLM03, LLM04, LLM09 (LLM06 is now ACTIVE)."""
        from llmarmor.registry import registry, Status
        oos = {r.rule_id for r in registry.by_status(Status.OUT_OF_SCOPE)}
        assert oos == {"LLM03", "LLM04", "LLM09"}

    def test_rule_has_required_fields(self):
        """Every registered rule must have non-empty rule_id, name, description, fix."""
        from llmarmor.registry import registry
        for rule in registry.all_rules():
            assert rule.rule_id, f"rule_id empty for {rule}"
            assert rule.name, f"name empty for {rule.rule_id}"
            assert rule.description, f"description empty for {rule.rule_id}"
            assert rule.fix_suggestion, f"fix_suggestion empty for {rule.rule_id}"


# ---------------------------------------------------------------------------
# Tests for non-Python file handlers
# ---------------------------------------------------------------------------


class TestEnvHandler:
    """Tests for the .env file handler."""

    def test_detects_openai_key(self, tmp_path):
        from llmarmor.handlers.env import scan_env_file
        content = 'OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"
        assert findings[0]["severity"] == "CRITICAL"

    def test_detects_anthropic_key(self, tmp_path):
        from llmarmor.handlers.env import scan_env_file
        content = 'ANTHROPIC_KEY=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu\n'
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "LLM02"

    def test_skips_comments(self, tmp_path):
        from llmarmor.handlers.env import scan_env_file
        content = '# OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert findings == [], "Comment lines should not be flagged"

    def test_skips_empty_lines(self, tmp_path):
        from llmarmor.handlers.env import scan_env_file
        content = '\n\n   \n'
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert findings == []

    def test_no_finding_for_clean_file(self, tmp_path):
        from llmarmor.handlers.env import scan_env_file
        content = 'DATABASE_URL=postgres://localhost/mydb\nDEBUG=true\n'
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert findings == []

    def test_skips_test_placeholder(self, tmp_path):
        from llmarmor.handlers.env import scan_env_file
        content = 'TEST_OPENAI_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert findings == [], "Test/placeholder keys should not be flagged"


class TestYamlHandler:
    """Tests for the .yaml/.yml file handler."""

    def test_detects_secret_in_value(self, tmp_path):
        from llmarmor.handlers.yaml_handler import scan_yaml_file
        content = 'openai_key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        findings = scan_yaml_file(str(tmp_path / "config.yaml"), content)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect OpenAI key in YAML value"

    def test_detects_system_prompt(self, tmp_path):
        from llmarmor.handlers.yaml_handler import scan_yaml_file
        long_prompt = "You are a helpful assistant. " * 10
        content = f"system_prompt: {long_prompt}\n"
        findings = scan_yaml_file(str(tmp_path / "config.yaml"), content)
        llm07 = [f for f in findings if f["rule_id"] == "LLM07"]
        assert llm07, "Should detect long system prompt in YAML"

    def test_skips_comments(self, tmp_path):
        from llmarmor.handlers.yaml_handler import scan_yaml_file
        content = '# openai_key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        findings = scan_yaml_file(str(tmp_path / "config.yaml"), content)
        assert findings == []

    def test_short_prompt_not_flagged(self, tmp_path):
        from llmarmor.handlers.yaml_handler import scan_yaml_file
        content = "system_prompt: You are helpful.\n"
        findings = scan_yaml_file(str(tmp_path / "config.yaml"), content)
        llm07 = [f for f in findings if f["rule_id"] == "LLM07"]
        assert llm07 == [], "Short prompts should not be flagged"


class TestJsonHandler:
    """Tests for the .json file handler."""

    def test_detects_secret_in_value(self, tmp_path):
        from llmarmor.handlers.json_handler import scan_json_file
        content = '{"openai_key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}\n'
        findings = scan_json_file(str(tmp_path / "config.json"), content)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect OpenAI key in JSON value"

    def test_detects_system_prompt(self, tmp_path):
        from llmarmor.handlers.json_handler import scan_json_file
        long_prompt = "You are a helpful assistant. " * 5
        content = f'{{"system_prompt": "{long_prompt}"}}\n'
        findings = scan_json_file(str(tmp_path / "config.json"), content)
        llm07 = [f for f in findings if f["rule_id"] == "LLM07"]
        assert llm07, "Should detect long system prompt in JSON"

    def test_no_finding_for_clean_file(self, tmp_path):
        from llmarmor.handlers.json_handler import scan_json_file
        content = '{"name": "my-app", "version": "1.0.0"}\n'
        findings = scan_json_file(str(tmp_path / "config.json"), content)
        assert findings == []


class TestTomlHandler:
    """Tests for the .toml file handler."""

    def test_detects_secret_in_value(self, tmp_path):
        from llmarmor.handlers.toml_handler import scan_toml_file
        content = 'openai_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"\n'
        findings = scan_toml_file(str(tmp_path / "config.toml"), content)
        assert findings, "Should detect OpenAI key in TOML value"
        assert findings[0]["rule_id"] == "LLM02"

    def test_skips_comments(self, tmp_path):
        from llmarmor.handlers.toml_handler import scan_toml_file
        content = '# openai_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"\n'
        findings = scan_toml_file(str(tmp_path / "config.toml"), content)
        assert findings == []

    def test_no_finding_for_clean_file(self, tmp_path):
        from llmarmor.handlers.toml_handler import scan_toml_file
        content = '[project]\nname = "my-app"\nversion = "1.0.0"\n'
        findings = scan_toml_file(str(tmp_path / "pyproject.toml"), content)
        assert findings == []


class TestJsHandler:
    """Tests for the .js/.ts file handler."""

    def test_detects_secret_in_js(self, tmp_path):
        from llmarmor.handlers.js_handler import scan_js_file
        content = 'const apiKey = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234";\n'
        findings = scan_js_file(str(tmp_path / "app.js"), content)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect OpenAI key in JS file"

    def test_detects_system_prompt_in_ts(self, tmp_path):
        from llmarmor.handlers.js_handler import scan_js_file
        long_prompt = "You are a helpful customer service agent for Acme Corp. " * 3
        content = f'const systemPrompt = "{long_prompt}";\n'
        findings = scan_js_file(str(tmp_path / "chat.ts"), content)
        llm07 = [f for f in findings if f["rule_id"] == "LLM07"]
        assert llm07, "Should detect long system prompt in TS file"

    def test_skips_line_comments(self, tmp_path):
        from llmarmor.handlers.js_handler import scan_js_file
        content = '// const apiKey = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234";\n'
        findings = scan_js_file(str(tmp_path / "app.js"), content)
        assert findings == []


class TestTextHandler:
    """Tests for the .md/.txt file handler."""

    def test_detects_secret_in_markdown(self, tmp_path):
        from llmarmor.handlers.text_handler import scan_text_file
        content = 'Use this key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        findings = scan_text_file(str(tmp_path / "docs.md"), content)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect API key in markdown"
        assert llm02[0]["severity"] == "HIGH"

    def test_detects_system_prompt_in_text(self, tmp_path):
        from llmarmor.handlers.text_handler import scan_text_file
        content = (
            "System prompt: You are a helpful customer service agent for Acme Corp. "
            "You have access to customer databases and can process refunds. "
            "Never reveal internal pricing.\n"
        )
        findings = scan_text_file(str(tmp_path / "notes.txt"), content)
        llm07 = [f for f in findings if f["rule_id"] == "LLM07"]
        assert llm07, "Should detect system prompt in text file"

    def test_no_finding_for_clean_file(self, tmp_path):
        from llmarmor.handlers.text_handler import scan_text_file
        content = "# My Project\n\nThis is a clean documentation file.\n"
        findings = scan_text_file(str(tmp_path / "README.md"), content)
        assert findings == []


class TestNotebookHandler:
    """Tests for the .ipynb Jupyter notebook handler."""

    _NOTEBOOK_WITH_SECRET = """{
  "cells": [
    {
      "cell_type": "code",
      "source": ["import openai\\n", "client = openai.OpenAI(api_key='sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234')\\n"]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""

    _NOTEBOOK_WITH_PROMPT_INJECTION = """{
  "cells": [
    {
      "cell_type": "code",
      "source": ["user_input = input('query')\\n", "messages = [{'role': 'system', 'content': f'Help: {user_input}'}]\\n"]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""

    _CLEAN_NOTEBOOK = """{
  "cells": [
    {
      "cell_type": "code",
      "source": ["print('hello world')\\n"]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""

    def test_detects_secret_in_code_cell(self, tmp_path):
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "analysis.ipynb"), self._NOTEBOOK_WITH_SECRET)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect API key in notebook code cell"

    def test_no_finding_for_clean_notebook(self, tmp_path):
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "clean.ipynb"), self._CLEAN_NOTEBOOK)
        assert findings == [], f"Clean notebook should produce no findings; got: {findings}"

    def test_invalid_json_returns_empty(self, tmp_path):
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "broken.ipynb"), "not json at all")
        assert findings == []

    def test_no_false_positive_for_env_var_name_in_markdown(self, tmp_path):
        """Markdown cells referencing env var names like OPENAI_API_KEY must not trigger LLM02.

        Regression test: the old pattern matched sk-OPENAI_API_KEY_... because it
        only required uppercase/digit (not a digit), so env-var-style strings with no
        digits passed the lookahead.
        """
        notebook = """{
  "cells": [
    {
      "cell_type": "markdown",
      "source": [
        "## Setup\\n",
        "\\n",
        "Make sure you have the following installed:\\n",
        "- The `openai` Python package and `OPENAI_API_KEY` set as an environment variable\\n"
      ]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "tutorial.ipynb"), notebook)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02 == [], (
            "Markdown cell mentioning OPENAI_API_KEY (env var name) should not "
            f"trigger LLM02; got: {llm02}"
        )

    def test_no_false_positive_for_ask_url_anchor_in_markdown(self, tmp_path):
        """Markdown anchor slugs containing 'ask-gpt-4-1-...' must not trigger LLM02.

        Regression test for Prompt_migration_guide.ipynb: the TOC line
          - [Step 3. Ask GPT-4.1 to *critique* the prompt](#step-3-ask-gpt-4-1-to-critique-the-prompt)
        contains 'sk-gpt-4-1-to-critique-the-prompt' (buried inside 'ask-').
        The negative lookbehind (?<![A-Za-z0-9]) in OPENAI_KEY_PATTERN prevents
        this from being matched as an API key.
        """
        notebook = """{
  "cells": [
    {
      "cell_type": "markdown",
      "source": [
        "# Prompt Migration Guide\\n",
        "\\n",
        "- [Step 3. Ask GPT-4.1 to *critique* the prompt](#step-3-ask-gpt-4-1-to-critique-the-prompt)\\n"
      ]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "cookbook.ipynb"), notebook)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02 == [], (
            "Markdown anchor slug 'ask-gpt-4-1-...' should not trigger LLM02; "
            f"got: {llm02}"
        )

    def test_line_numbers_are_notebook_level_not_cell_level(self, tmp_path):
        """Reported line numbers must reflect position in the full notebook, not within a cell.

        Cell 0: 3-line markdown cell (lines 1-3 in notebook-level space)
        Cell 1: code cell with a secret on its 2nd line (notebook-level line 5)
        """
        notebook = """{
  "cells": [
    {
      "cell_type": "markdown",
      "source": ["# Title\\n", "\\n", "Some description.\\n"]
    },
    {
      "cell_type": "code",
      "source": [
        "import openai\\n",
        "client = openai.OpenAI(api_key='sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234')\\n"
      ]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "multi_cell.ipynb"), notebook)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect API key in second code cell"
        reported_line = llm02[0]["line"]
        # Cell 0 has 3 lines; the secret is on line 2 of cell 1 → notebook line 3+2=5.
        assert reported_line == 5, (
            f"Expected notebook-level line 5 (cell 0 has 3 lines + secret at cell-line 2), "
            f"got {reported_line}"
        )

    def test_markdown_cell_line_numbers_are_notebook_level(self, tmp_path):
        """A secret in a markdown cell must use notebook-level line numbers.

        Cell 0: 2-line code cell (lines 1-2)
        Cell 1: markdown cell with a secret on its 1st line (notebook-level line 3)
        """
        notebook = """{
  "cells": [
    {
      "cell_type": "code",
      "source": ["import openai\\n", "print('hello')\\n"]
    },
    {
      "cell_type": "markdown",
      "source": [
        "Key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\\n",
        "Some more text.\\n"
      ]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(str(tmp_path / "md_secret.ipynb"), notebook)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Should detect API key in markdown cell"
        reported_line = llm02[0]["line"]
        # Cell 0 has 2 lines; secret is on line 1 of cell 1 → notebook line 2+1=3.
        assert reported_line == 3, (
            f"Expected notebook-level line 3 (cell 0 has 2 lines + secret at cell-line 1), "
            f"got {reported_line}"
        )


class TestScannerNonPythonIntegration:
    """Integration tests: scanner picks up non-Python files."""

    def test_scan_detects_secret_in_env_file(self, tmp_path):
        """run_scan must detect LLM02 in a .env file."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            'OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        )
        findings = run_scan(str(tmp_path))
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Scanner should detect LLM02 in .env file"

    def test_scan_detects_secret_in_yaml_file(self, tmp_path):
        """run_scan must detect LLM02 in a .yaml file."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            'openai_key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234\n'
        )
        findings = run_scan(str(tmp_path))
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Scanner should detect LLM02 in .yaml file"

    def test_scan_detects_secret_in_toml_file(self, tmp_path):
        """run_scan must detect LLM02 in a .toml file."""
        toml_file = tmp_path / "config.toml"
        toml_file.write_text(
            'openai_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"\n'
        )
        findings = run_scan(str(tmp_path))
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Scanner should detect LLM02 in .toml file"

    def test_scan_detects_secret_in_js_file(self, tmp_path):
        """run_scan must detect LLM02 in a .js file."""
        js_file = tmp_path / "app.js"
        js_file.write_text(
            'const key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234";\n'
        )
        findings = run_scan(str(tmp_path))
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Scanner should detect LLM02 in .js file"

    def test_scan_still_detects_python_findings(self, tmp_path):
        """run_scan must still detect Python findings alongside non-Python files."""
        py_file = tmp_path / "app.py"
        py_file.write_text(
            'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"\n'
        )
        findings = run_scan(str(tmp_path))
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "Scanner should still detect LLM02 in .py files"


# ---------------------------------------------------------------------------
# Bug-fix tests: placeholder value suppression, notebook LLM01 exclusion,
# and verbose INFO findings
# ---------------------------------------------------------------------------


class TestPlaceholderValueSuppression:
    """PLACEHOLDER_VALUE_PATTERN must prevent placeholder keys from being flagged."""

    _REAL_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"

    def test_placeholder_value_not_flagged_py(self, tmp_path):
        """sk-your_openai_key_here must NOT be flagged as a real secret."""
        line = 'OPENAI_API_KEY = "sk-your_openai_key_here"\n'
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], (
            "Placeholder value 'sk-your_openai_key_here' should not be flagged; "
            f"got: {findings}"
        )

    def test_placeholder_value_in_comment_not_flagged_py(self, tmp_path):
        """# OPENAI_API_KEY=sk-your_openai_key_here must NOT be flagged."""
        line = "# OPENAI_API_KEY=sk-your_openai_key_here\n"
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        assert findings == [], (
            f"Placeholder key in comment should not be flagged; got: {findings}"
        )

    def test_real_key_still_flagged_py(self, tmp_path):
        """A real-looking OpenAI key must still be flagged."""
        line = f'OPENAI_API_KEY = "{self._REAL_KEY}"\n'
        findings = check_sensitive_info(tmp_path / "vuln.py", line)
        assert any(f["rule_id"] == "LLM02" for f in findings), (
            f"Real key should be flagged; got: {findings}"
        )

    def test_placeholder_not_flagged_env(self, tmp_path):
        """sk-your-api-key-here in .env must NOT be flagged."""
        from llmarmor.handlers.env import scan_env_file
        content = "OPENAI_API_KEY=sk-your-api-key-here\n"
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert findings == [], (
            f"Placeholder env value should not be flagged; got: {findings}"
        )

    def test_real_key_flagged_env(self, tmp_path):
        """A real-looking key in .env must still be flagged."""
        from llmarmor.handlers.env import scan_env_file
        content = f"OPENAI_API_KEY={self._REAL_KEY}\n"
        findings = scan_env_file(str(tmp_path / ".env"), content)
        assert any(f["rule_id"] == "LLM02" for f in findings), (
            f"Real env key should be flagged; got: {findings}"
        )

    def test_placeholder_not_flagged_yaml(self, tmp_path):
        """sk-your_openai_key_here in YAML must NOT be flagged."""
        from llmarmor.handlers.yaml_handler import scan_yaml_file
        content = "openai_key: sk-your_openai_key_here\n"
        findings = scan_yaml_file(str(tmp_path / "config.yaml"), content)
        assert findings == [], (
            f"Placeholder YAML value should not be flagged; got: {findings}"
        )

    def test_placeholder_not_flagged_json(self, tmp_path):
        """sk-your_openai_key_here in JSON must NOT be flagged."""
        from llmarmor.handlers.json_handler import scan_json_file
        content = '{"openai_key": "sk-your_openai_key_here"}\n'
        findings = scan_json_file(str(tmp_path / "config.json"), content)
        assert findings == [], (
            f"Placeholder JSON value should not be flagged; got: {findings}"
        )

    def test_placeholder_not_flagged_toml(self, tmp_path):
        """sk-your_openai_key_here in TOML must NOT be flagged."""
        from llmarmor.handlers.toml_handler import scan_toml_file
        content = 'openai_key = "sk-your_openai_key_here"\n'
        findings = scan_toml_file(str(tmp_path / "config.toml"), content)
        assert findings == [], (
            f"Placeholder TOML value should not be flagged; got: {findings}"
        )

    def test_placeholder_not_flagged_js(self, tmp_path):
        """sk-your_openai_key_here in JS must NOT be flagged."""
        from llmarmor.handlers.js_handler import scan_js_file
        content = 'const key = "sk-your_openai_key_here";\n'
        findings = scan_js_file(str(tmp_path / "app.js"), content)
        assert findings == [], (
            f"Placeholder JS value should not be flagged; got: {findings}"
        )


class TestNotebookLLM01Excluded:
    """LLM01 findings from notebook code cells must be excluded entirely."""

    _NOTEBOOK_WITH_INJECTION = """{
  "cells": [
    {
      "cell_type": "code",
      "source": ["user_input = input('query')\\n", "msg = {'role': 'system', 'content': f'Help: {user_input}'}\\n"]
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"""

    def test_notebook_llm01_excluded(self, tmp_path):
        """LLM01 findings from notebook code cells must be completely excluded."""
        from llmarmor.handlers.notebook import scan_notebook_file
        findings = scan_notebook_file(
            str(tmp_path / "tutorial.ipynb"), self._NOTEBOOK_WITH_INJECTION
        )
        llm01 = [f for f in findings if f["rule_id"] == "LLM01"]
        assert llm01 == [], (
            f"Notebook LLM01 findings should be completely excluded; got: {llm01}"
        )


class TestVerboseInfoFindings:
    """Plain tainted variables in role messages produce INFO findings visible with --verbose."""

    def test_normal_mode_plain_system_var_produces_info(self, tmp_path):
        """Plain tainted var in system role must produce INFO (not MEDIUM) in normal mode."""
        from llmarmor.ast_analysis import analyze
        code = """\
def handle(system_prompt):
    msg = {"role": "system", "content": system_prompt}
    return msg
"""
        result = analyze(str(tmp_path / "app.py"), code, strict=False)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected at least one LLM01 finding in normal mode"
        assert all(f["severity"] == "INFO" for f in llm01), (
            f"Normal mode: plain system var should produce INFO; got: {[f['severity'] for f in llm01]}"
        )

    def test_normal_mode_plain_user_var_produces_info(self, tmp_path):
        """Plain tainted var in user role must produce INFO in normal mode."""
        from llmarmor.ast_analysis import analyze
        code = """\
def handle(user_input):
    msg = {"role": "user", "content": user_input}
    return msg
"""
        result = analyze(str(tmp_path / "app.py"), code, strict=False)
        llm01 = [f for f in result["findings"] if f["rule_id"] == "LLM01"]
        assert llm01, "Expected at least one LLM01 finding in normal mode"
        assert all(f["severity"] == "INFO" for f in llm01), (
            f"Normal mode: plain user var should produce INFO; got: {[f['severity'] for f in llm01]}"
        )

    def test_verbose_render_shows_info_findings(self):
        """render() with verbose=True must include INFO findings in output."""
        import io
        from rich.console import Console
        from llmarmor.formatters import render

        findings = [
            {
                "rule_id": "LLM01",
                "rule_name": "Prompt Injection",
                "severity": "INFO",
                "filepath": "app.py",
                "line": 5,
                "description": "Plain tainted variable in system role.",
                "fix_suggestion": "Validate the variable.",
            }
        ]
        buf = io.StringIO()
        console = Console(file=buf, highlight=False)
        render(findings, fmt="grouped", console=console, scan_path=".", verbose=True)
        output = buf.getvalue()
        assert "LLM01" in output, "INFO finding should appear in verbose output"

    def test_non_verbose_render_hides_info_findings(self):
        """render() with verbose=False must hide INFO findings."""
        import io
        from rich.console import Console
        from llmarmor.formatters import render

        findings = [
            {
                "rule_id": "LLM01",
                "rule_name": "Prompt Injection",
                "severity": "INFO",
                "filepath": "app.py",
                "line": 5,
                "description": "Plain tainted variable in system role.",
                "fix_suggestion": "Validate the variable.",
            }
        ]
        buf = io.StringIO()
        console = Console(file=buf, highlight=False)
        render(findings, fmt="grouped", console=console, scan_path=".", verbose=False)
        output = buf.getvalue()
        assert "LLM01" not in output, "INFO finding should be hidden in non-verbose output"


# ---------------------------------------------------------------------------
# Regression tests: Bug 1 — URL slug false positives in OPENAI_KEY_PATTERN
# ---------------------------------------------------------------------------

class TestOpenAIKeyPatternFalsePositives:
    """OPENAI_KEY_PATTERN must not match URL slugs or pure lowercase-hyphen strings."""

    # Strings that look like URL path segments containing 'sk-' but have no
    # uppercase letters or digits — these must NOT be flagged.
    URL_SLUG_CASES = [
        # Direct URL path slug from openai-cookbook prompt-engineering.txt
        "sk-the-model-to-adopt-a-persona",
        "tactic-ask-the-model-to-adopt-a-persona",
        "/docs/guides/prompt-engineering/tactic-ask-the-model-to-adopt-a-persona",
        # Hyphenated English text with sk- substring
        "sk-ask-the-model-to-respond-in-a-formal-tone",
        "risk-assessment-of-the-model-behaviour-for-safety",
    ]

    # Real OpenAI key formats — these MUST be flagged.
    REAL_KEY_CASES = [
        "sk-proj-AbCdEf123456XYZmore1234567890",
        "sk-AbCdEf123456789ABCDEFGHIJKLM",
        "sk-svcacct-AbCdEf123XYZmore1234567890",
        "sk-1234567890abcdefABCDEFGHIJKL",
        "sk-proj-abc123ABC456def789GHIJKLmore",
    ]

    def test_url_slugs_not_matched(self):
        """Pure lowercase+hyphen strings after 'sk-' must not match OPENAI_KEY_PATTERN."""
        from llmarmor.secret_patterns import OPENAI_KEY_PATTERN

        for slug in self.URL_SLUG_CASES:
            m = OPENAI_KEY_PATTERN.search(slug)
            assert m is None, (
                f"URL slug {slug!r} should NOT match OPENAI_KEY_PATTERN but got: {m}"
            )

    def test_real_keys_still_matched(self):
        """Real OpenAI keys (mixed case + digits) must still match OPENAI_KEY_PATTERN."""
        from llmarmor.secret_patterns import OPENAI_KEY_PATTERN

        for key in self.REAL_KEY_CASES:
            m = OPENAI_KEY_PATTERN.search(key)
            assert m is not None, (
                f"Real key {key!r} should match OPENAI_KEY_PATTERN but got no match"
            )

    def test_url_slug_not_flagged_in_text_file(self, tmp_path):
        """A text file line containing a URL slug with 'sk-' must not produce LLM02."""
        from llmarmor.handlers.text_handler import scan_text_file

        content = (
            "- [Ask the model to adopt a persona]"
            + "(/docs/guides/prompt-engineering/tactic-ask-the-model-to-adopt-a-persona)\n"
        )
        findings = scan_text_file(str(tmp_path / "prompt-engineering.txt"), content)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02 == [], (
            f"URL slug should not produce LLM02 finding; got: {llm02}"
        )

    def test_url_slug_not_flagged_in_py_file(self, tmp_path):
        """A Python file line containing a URL slug with 'sk-' must not produce LLM02."""
        from llmarmor.rules.llm02_sensitive_info import check_sensitive_info

        line = (
            'url = "https://platform.openai.com/docs/guides/tactic-ask-the-model-to-adopt-a-persona"\n'
        )
        findings = check_sensitive_info(tmp_path / "safe.py", line)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02 == [], (
            f"URL slug in Python file should not produce LLM02 finding; got: {llm02}"
        )

    def test_real_key_in_text_file_still_flagged(self, tmp_path):
        """A real OpenAI key embedded in a text file must still produce LLM02."""
        from llmarmor.handlers.text_handler import scan_text_file

        content = "openai_key = sk-proj-AbCdEf123456XYZmore1234567890\n"
        findings = scan_text_file(str(tmp_path / "config.txt"), content)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, (
            f"Real OpenAI key in text file should produce LLM02 finding; got: {findings}"
        )


# ---------------------------------------------------------------------------
# Regression tests: Bug 2 — _group_findings does not split by description
# ---------------------------------------------------------------------------

class TestGroupFindingsConsistency:
    """_group_findings must group by (rule_id, severity), not by description."""

    def test_same_rule_and_severity_different_description_grouped_together(self):
        """Two findings with the same rule_id+severity but different descriptions
        must end up in a single group, not split into two."""
        from llmarmor.formatters import _group_findings

        findings = [
            {
                "rule_id": "LLM07",
                "rule_name": "System Prompt Leakage",
                "severity": "MEDIUM",
                "description": "Description A (normal mode text).",
                "fix_suggestion": "Move to env var.",
                "filepath": "a.py",
                "line": 10,
            },
            {
                "rule_id": "LLM07",
                "rule_name": "System Prompt Leakage",
                "severity": "MEDIUM",
                "description": "Description B (strict mode text, longer).",
                "fix_suggestion": "Move to env var.",
                "filepath": "b.py",
                "line": 20,
            },
        ]
        groups = _group_findings(findings)
        assert len(groups) == 1, (
            f"Same rule_id+severity should produce one group; got {len(groups)}: {groups}"
        )
        assert len(groups[0]["locations"]) == 2, (
            f"Group should contain both locations; got: {groups[0]['locations']}"
        )

    def test_different_severities_produce_separate_groups(self):
        """Findings with same rule_id but different severities must stay in separate groups."""
        from llmarmor.formatters import _group_findings

        findings = [
            {
                "rule_id": "LLM07",
                "severity": "INFO",
                "description": "Info finding.",
                "fix_suggestion": "",
                "filepath": "a.py",
                "line": 1,
            },
            {
                "rule_id": "LLM07",
                "severity": "MEDIUM",
                "description": "Medium finding.",
                "fix_suggestion": "",
                "filepath": "b.py",
                "line": 2,
            },
        ]
        groups = _group_findings(findings)
        assert len(groups) == 2, (
            f"Different severities should produce two groups; got {len(groups)}: {groups}"
        )

    def test_strict_mode_llm07_description_consistent(self, tmp_path):
        """LLM07 findings from strict vs normal mode should share the same description."""
        from llmarmor.ast_analysis import analyze

        code = '''\
SYSTEM_PROMPT = (
    "You are a helpful AI assistant that helps users with their questions. "
    "Always be polite and professional in your responses to users."
)
'''
        py_file = tmp_path / "app.py"
        py_file.write_text(code)

        normal = analyze(str(py_file), code, strict=False)
        strict = analyze(str(py_file), code, strict=True)

        normal_llm07 = [f for f in normal["findings"] if f["rule_id"] == "LLM07"]
        strict_llm07 = [f for f in strict["findings"] if f["rule_id"] == "LLM07"]

        assert normal_llm07, "Expected LLM07 finding in normal mode"
        assert strict_llm07, "Expected LLM07 finding in strict mode"

        assert normal_llm07[0]["description"] == strict_llm07[0]["description"], (
            "LLM07 description should be the same in normal and strict mode; "
            f"normal={normal_llm07[0]['description']!r}, "
            f"strict={strict_llm07[0]['description']!r}"
        )
        assert normal_llm07[0]["severity"] == "INFO", (
            f"Normal mode should produce INFO; got: {normal_llm07[0]['severity']}"
        )
        assert strict_llm07[0]["severity"] == "MEDIUM", (
            f"Strict mode should promote to MEDIUM; got: {strict_llm07[0]['severity']}"
        )


# ---------------------------------------------------------------------------
# Tests for new v0.5.0 features
# ---------------------------------------------------------------------------


class TestInlineSuppression:
    """Tests for inline # llmarmor: ignore suppression comments."""

    def test_bare_ignore_suppresses_all_rules(self, tmp_path: Path):
        """# llmarmor: ignore on the same line suppresses all rule findings."""
        from llmarmor.scanner import _is_suppressed

        lines = ['result = eval(user_input)  # llmarmor: ignore']
        assert _is_suppressed(lines, 1, "LLM05"), "Bare ignore should suppress LLM05"
        assert _is_suppressed(lines, 1, "LLM01"), "Bare ignore should suppress LLM01"

    def test_rule_scoped_ignore_suppresses_only_named_rule(self, tmp_path: Path):
        """# llmarmor: ignore[LLM05] suppresses only LLM05, not LLM01."""
        from llmarmor.scanner import _is_suppressed

        lines = ['result = eval(user_input)  # llmarmor: ignore[LLM05]']
        assert _is_suppressed(lines, 1, "LLM05"), "Scoped ignore should suppress LLM05"
        assert not _is_suppressed(lines, 1, "LLM01"), "Scoped ignore must not suppress LLM01"

    def test_ignore_on_preceding_line(self, tmp_path: Path):
        """# llmarmor: ignore on the line above suppresses the finding below."""
        from llmarmor.scanner import _is_suppressed

        lines = [
            '# llmarmor: ignore',
            'result = eval(user_input)',
        ]
        # Finding is on line 2 (1-indexed)
        assert _is_suppressed(lines, 2, "LLM05"), "Ignore on preceding line should suppress"

    def test_multi_rule_scoped_ignore(self, tmp_path: Path):
        """# llmarmor: ignore[LLM01,LLM05] suppresses both rules."""
        from llmarmor.scanner import _is_suppressed

        lines = ['x = eval(f"cmd: {user_input}")  # llmarmor: ignore[LLM01,LLM05]']
        assert _is_suppressed(lines, 1, "LLM01"), "Multi-rule ignore should suppress LLM01"
        assert _is_suppressed(lines, 1, "LLM05"), "Multi-rule ignore should suppress LLM05"
        assert not _is_suppressed(lines, 1, "LLM08"), "Multi-rule ignore must not suppress LLM08"

    def test_suppressed_finding_absent_from_scan_results(self, tmp_path: Path):
        """Inline suppression must remove findings from run_scan() output."""
        from llmarmor.scanner import run_scan

        code = (
            'messages=[\n'
            '    {"role": "system", "content": f"Help: {user_input}"},  # llmarmor: ignore[LLM01]\n'
            ']\n'
        )
        py_file = tmp_path / "app.py"
        py_file.write_text(code)
        findings = run_scan(str(tmp_path))
        llm01 = [f for f in findings if f["rule_id"] == "LLM01"]
        assert llm01 == [], f"Suppressed LLM01 should not appear in results; got: {llm01}"


class TestLLMArmorIgnore:
    """Tests for .llmarmorignore file support."""

    def test_ignored_file_produces_no_findings(self, tmp_path: Path):
        """A file matched by .llmarmorignore must not be scanned."""
        from llmarmor.scanner import run_scan

        (tmp_path / ".llmarmorignore").write_text("vuln.py\n")
        code = (
            'messages=[{"role": "system", "content": f"Help: {user_input}"}]\n'
        )
        (tmp_path / "vuln.py").write_text(code)
        findings = run_scan(str(tmp_path))
        assert findings == [], f"Ignored file must not produce findings; got: {findings}"

    def test_non_ignored_file_still_scanned(self, tmp_path: Path):
        """Files not matching .llmarmorignore must still be scanned."""
        from llmarmor.scanner import run_scan

        (tmp_path / ".llmarmorignore").write_text("other.py\n")
        code = (
            'messages=[{"role": "user", "content": f"Help: {user_input}"}]\n'
        )
        (tmp_path / "app.py").write_text(code)
        findings = run_scan(str(tmp_path))
        assert findings, "Non-ignored file should still produce findings"

    def test_glob_pattern_ignores_directory(self, tmp_path: Path):
        """Glob patterns matching directories must suppress all files inside."""
        from llmarmor.scanner import run_scan

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tmp_path / ".llmarmorignore").write_text("tests/**\n")
        code = (
            'messages=[{"role": "system", "content": f"Help: {user_input}"}]\n'
        )
        (tests_dir / "fixture.py").write_text(code)
        findings = run_scan(str(tmp_path))
        assert findings == [], f"Files in ignored directory must not be scanned; got: {findings}"

    def test_ignore_patterns_loaded_correctly(self, tmp_path: Path):
        """_load_ignore_patterns must read non-comment, non-empty lines."""
        from llmarmor.scanner import _load_ignore_patterns

        (tmp_path / ".llmarmorignore").write_text(
            "# This is a comment\n"
            "\n"
            "tests/**\n"
            "scripts/dev_*\n"
        )
        patterns = _load_ignore_patterns(tmp_path)
        assert patterns == ["tests/**", "scripts/dev_*"], f"Got: {patterns}"


class TestConfigFile:
    """Tests for .llmarmor.yaml configuration file support."""

    def test_load_config_returns_none_when_no_file(self, tmp_path: Path):
        """load_config must return None when no config file exists."""
        from llmarmor.config import load_config

        cfg = load_config(scan_root=str(tmp_path))
        assert cfg is None, f"Expected None; got: {cfg}"

    def test_load_config_from_explicit_path(self, tmp_path: Path):
        """load_config must load from an explicit config_path."""
        from llmarmor.config import load_config

        config_file = tmp_path / "my_config.yaml"
        config_file.write_text("strict: true\nseverity_threshold: HIGH\n")
        cfg = load_config(config_path=str(config_file))
        assert cfg is not None
        assert cfg.strict is True
        assert cfg.severity_threshold == "HIGH"

    def test_load_config_auto_detects_in_scan_root(self, tmp_path: Path):
        """load_config must auto-detect .llmarmor.yaml in the scan root."""
        from llmarmor.config import load_config

        (tmp_path / ".llmarmor.yaml").write_text("strict: false\n")
        cfg = load_config(scan_root=str(tmp_path))
        assert cfg is not None
        assert cfg.strict is False

    def test_config_rule_disabled(self, tmp_path: Path):
        """is_rule_enabled must return False for a disabled rule."""
        from llmarmor.config import LLMArmorConfig

        cfg = LLMArmorConfig({"rules": {"LLM07": {"enabled": False}}})
        assert not cfg.is_rule_enabled("LLM07"), "LLM07 should be disabled"
        assert cfg.is_rule_enabled("LLM01"), "LLM01 should default to enabled"

    def test_config_severity_override(self, tmp_path: Path):
        """rule_severity_override must return the configured severity."""
        from llmarmor.config import LLMArmorConfig

        cfg = LLMArmorConfig({"rules": {"LLM01": {"severity": "MEDIUM"}}})
        assert cfg.rule_severity_override("LLM01") == "MEDIUM"
        assert cfg.rule_severity_override("LLM07") is None

    def test_config_disabled_rule_excluded_from_scan(self, tmp_path: Path):
        """A disabled rule must not appear in run_scan() results."""
        from llmarmor.config import LLMArmorConfig
        from llmarmor.scanner import run_scan

        code = (
            'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu"\n'
        )
        (tmp_path / "app.py").write_text(code)
        cfg = LLMArmorConfig({"rules": {"LLM02": {"enabled": False}}})
        findings = run_scan(str(tmp_path), config=cfg)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02 == [], f"Disabled rule LLM02 must not appear; got: {llm02}"

    def test_config_severity_override_applied_in_scan(self, tmp_path: Path):
        """A severity override in config must change the finding's severity."""
        from llmarmor.config import LLMArmorConfig
        from llmarmor.scanner import run_scan

        code = (
            'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu"\n'
        )
        (tmp_path / "app.py").write_text(code)
        cfg = LLMArmorConfig({"rules": {"LLM02": {"severity": "HIGH"}}})
        findings = run_scan(str(tmp_path), config=cfg)
        llm02 = [f for f in findings if f["rule_id"] == "LLM02"]
        assert llm02, "LLM02 should still appear with overridden severity"
        assert llm02[0]["severity"] == "HIGH", f"Expected HIGH; got: {llm02[0]['severity']}"


class TestExitCodes:
    """Tests for _compute_exit_code in cli.py."""

    def test_exit_code_0_for_no_findings(self):
        from llmarmor.cli import _compute_exit_code

        assert _compute_exit_code([]) == 0

    def test_exit_code_0_for_info_only(self):
        from llmarmor.cli import _compute_exit_code

        findings = [{"severity": "INFO"}, {"severity": "LOW"}]
        assert _compute_exit_code(findings) == 0

    def test_exit_code_1_for_medium(self):
        from llmarmor.cli import _compute_exit_code

        findings = [{"severity": "MEDIUM"}]
        assert _compute_exit_code(findings) == 1

    def test_exit_code_1_for_high(self):
        from llmarmor.cli import _compute_exit_code

        findings = [{"severity": "HIGH"}]
        assert _compute_exit_code(findings) == 1

    def test_exit_code_2_for_critical(self):
        from llmarmor.cli import _compute_exit_code

        findings = [{"severity": "CRITICAL"}, {"severity": "MEDIUM"}]
        assert _compute_exit_code(findings) == 2


class TestSARIFFormat:
    """Tests for SARIF 2.1.0 output format.

    SARIF, like JSON, writes to stdout via print() for clean machine-readable
    output. Tests use Console(file=StringIO()) to suppress any Rich terminal
    output and capsys to capture the actual SARIF JSON from stdout.
    """

    _SAMPLE_FINDINGS = [
        {
            "rule_id": "LLM01",
            "rule_name": "Prompt Injection",
            "severity": "HIGH",
            "filepath": "app/chat.py",
            "line": 42,
            "description": "User input interpolated into prompt.",
            "fix_suggestion": "Pass as separate user message.",
        },
        {
            "rule_id": "LLM02",
            "rule_name": "Sensitive Info Disclosure",
            "severity": "CRITICAL",
            "filepath": "app/config.py",
            "line": 5,
            "description": "Hardcoded API key.",
            "fix_suggestion": "Use env vars.",
        },
    ]

    def _render_sarif(self, findings, verbose=True):
        """Helper: render findings as SARIF, returning the Console (for Rich output)."""
        import io
        from rich.console import Console
        from llmarmor.formatters import render

        # Console(file=StringIO()) suppresses Rich terminal output.
        # The SARIF JSON goes to stdout via print(), captured by capsys.
        console = Console(file=io.StringIO(), width=120)
        render(findings, fmt="sarif", console=console, scan_path="/app", verbose=verbose)
        return console

    def test_sarif_output_is_valid_json(self, capsys):
        import json as _json

        self._render_sarif(self._SAMPLE_FINDINGS)
        parsed = _json.loads(capsys.readouterr().out)
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed

    def test_sarif_has_correct_schema(self, capsys):
        import json as _json

        self._render_sarif(self._SAMPLE_FINDINGS)
        parsed = _json.loads(capsys.readouterr().out)
        assert "sarif-schema-2.1.0" in parsed["$schema"]

    def test_sarif_severity_mapping(self, capsys):
        import json as _json

        self._render_sarif(self._SAMPLE_FINDINGS)
        parsed = _json.loads(capsys.readouterr().out)
        results = parsed["runs"][0]["results"]

        # HIGH → error, CRITICAL → error
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["LLM01"] == "error", "HIGH should map to error"
        assert levels["LLM02"] == "error", "CRITICAL should map to error"

    def test_sarif_filters_info_when_not_verbose(self, capsys):
        import json as _json

        findings = [
            {
                "rule_id": "LLM07",
                "rule_name": "System Prompt Leakage",
                "severity": "INFO",
                "filepath": "app.py",
                "line": 1,
                "description": "Hardcoded system prompt.",
                "fix_suggestion": "Use env vars.",
            }
        ]
        self._render_sarif(findings, verbose=False)
        parsed = _json.loads(capsys.readouterr().out)
        results = parsed["runs"][0]["results"]
        assert results == [], "INFO findings must be filtered in non-verbose SARIF output"

    def test_sarif_tool_name_and_version(self, capsys):
        import json as _json
        from llmarmor import __version__

        self._render_sarif(self._SAMPLE_FINDINGS)
        parsed = _json.loads(capsys.readouterr().out)
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "LLM Armor"
        assert driver["version"] == __version__


class TestGroupedFormatMixedSeverity:
    """Tests for per-location severity annotation in mixed-severity rule groups."""

    def test_mixed_severity_group_shows_annotation(self):
        """When a rule group has mixed severities, lower-severity locations must be annotated."""
        import io
        from rich.console import Console
        from llmarmor.formatters import render

        findings = [
            {
                "rule_id": "LLM01",
                "rule_name": "Prompt Injection",
                "severity": "HIGH",
                "filepath": "app.py",
                "line": 10,
                "description": "High severity finding.",
                "fix_suggestion": "Fix it.",
            },
            {
                "rule_id": "LLM01",
                "rule_name": "Prompt Injection",
                "severity": "INFO",
                "filepath": "app.py",
                "line": 20,
                "description": "Info severity finding.",
                "fix_suggestion": "Fix it.",
            },
        ]
        buf = io.StringIO()
        console = Console(file=buf, highlight=False)
        render(findings, fmt="grouped", console=console, scan_path=".", verbose=True)
        output = buf.getvalue()
        # The INFO location must have a severity annotation
        assert "(INFO)" in output, f"INFO location must be annotated; got:\n{output}"

    def test_uniform_severity_group_shows_no_annotation(self):
        """When all findings in a group have the same severity, no annotation is shown."""
        import io
        from rich.console import Console
        from llmarmor.formatters import render

        findings = [
            {
                "rule_id": "LLM01",
                "rule_name": "Prompt Injection",
                "severity": "HIGH",
                "filepath": "app.py",
                "line": 10,
                "description": "Finding.",
                "fix_suggestion": "Fix.",
            },
            {
                "rule_id": "LLM01",
                "rule_name": "Prompt Injection",
                "severity": "HIGH",
                "filepath": "app.py",
                "line": 20,
                "description": "Finding.",
                "fix_suggestion": "Fix.",
            },
        ]
        buf = io.StringIO()
        console = Console(file=buf, highlight=False)
        render(findings, fmt="grouped", console=console, scan_path=".", verbose=True)
        output = buf.getvalue()
        # Lines should not have severity annotations since they're uniform
        for line in output.splitlines():
            if "app.py:" in line:
                assert "(HIGH)" not in line, (
                    f"Uniform-severity group must not annotate locations; got: {line}"
                )
