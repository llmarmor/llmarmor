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
        """{"role": "user", "content": tainted_var} must NOT produce an AST LLM01 finding."""
        code = """\
user_input = input("prompt")
msg = {"role": "user", "content": user_input}
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "User role with standalone tainted variable should not produce AST LLM01 finding; "
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
        """{"role": "system", "content": system} must NOT be flagged.

        A plain variable reference is not string interpolation — no injection
        of instructions mixed with user data is occurring.
        """
        code = """\
def handle(system, user):
    msg = {"role": "system", "content": system}
    return msg
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            '{"role": "system", "content": system} (plain variable) should NOT be flagged; '
            f"got: {result['findings']}"
        )

    def test_user_role_plain_name_not_flagged(self, tmp_path: Path):
        """{"role": "user", "content": user} must NOT be flagged."""
        code = """\
def handle(user):
    msg = {"role": "user", "content": user}
    return msg
"""
        result = self._analyze(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            '{"role": "user", "content": user} (plain variable) should NOT be flagged; '
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
        """List of dicts with plain variable content must NOT be flagged.

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
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "messages list with plain variable content should NOT be flagged; "
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
        """In normal mode, plain tainted variable as system content must NOT be flagged."""
        code = """\
def handle(system, user):
    msg = {"role": "system", "content": system}
    return msg
"""
        result = self._analyze_normal(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Normal mode: plain tainted variable as system content should NOT be flagged; "
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
        """In normal mode, plain tainted variable as user content must NOT be flagged."""
        code = """\
def handle(user):
    msg = {"role": "user", "content": user}
    return msg
"""
        result = self._analyze_normal(tmp_path, code)
        assert not any(f["rule_id"] == "LLM01" for f in result["findings"]), (
            "Normal mode: plain tainted variable as user content should NOT be flagged; "
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
        """json format must produce valid JSON."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_json
        console = Console(file=StringIO(), width=120)
        format_json(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        parsed = _json.loads(captured.out)
        assert isinstance(parsed, list), f"JSON output should be a list; got: {type(parsed)}"
        assert len(parsed) == 3, f"Expected 3 findings in JSON; got: {len(parsed)}"

    def test_json_output_has_required_keys(self, capsys):
        """Each JSON finding must have the standard keys."""
        import json as _json
        from rich.console import Console
        from io import StringIO
        from llmarmor.formatters import format_json
        console = Console(file=StringIO(), width=120)
        format_json(self._SAMPLE_FINDINGS, console, "/some/path")
        captured = capsys.readouterr()
        parsed = _json.loads(captured.out)
        required_keys = {"rule_id", "rule_name", "severity", "filepath", "line", "description", "fix_suggestion"}
        for finding in parsed:
            missing = required_keys - finding.keys()
            assert not missing, f"JSON finding missing keys: {missing}"

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


class TestPathTruncation:
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
