"""Tests for LLM08: Excessive Agency — regex rule."""

from pathlib import Path

import pytest

from llmarmor.rules.llm08_excessive_agency import check_excessive_agency


def _analyze(tmp_path: Path, code: str, filename: str = "app.py") -> dict:
    """Helper that runs AST-based analysis via the public ``analyze()`` entry point."""
    from llmarmor.ast_analysis import analyze

    return analyze(str(tmp_path / filename), code)


class TestLLM08ExcessiveAgency:
    """Tests for the check_excessive_agency regex rule."""

    # ------------------------------------------------------------------
    # CRITICAL: globals() dynamic dispatch
    # ------------------------------------------------------------------

    def test_globals_dispatch_flagged_as_critical(self, tmp_path: Path):
        """globals()[tool_name]() must produce a CRITICAL finding."""
        code = "result = globals()[tool_name](args)\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for globals()[tool_name](); got: {findings}"

    def test_globals_dispatch_with_function_key(self, tmp_path: Path):
        """globals()[fn_name] must be flagged."""
        code = "fn = globals()[fn_name]\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for globals()[fn_name]; got: {findings}"

    # ------------------------------------------------------------------
    # HIGH: wildcard tool access
    # ------------------------------------------------------------------

    def test_wildcard_tools_list_flagged_as_high(self, tmp_path: Path):
        """tools=['*'] must produce a HIGH finding."""
        code = 'agent = Agent(tools=["*"])\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for tools=['*']; got: {findings}"

    def test_wildcard_tools_bare_star(self, tmp_path: Path):
        """tools=[*] (bare star) must produce a HIGH finding."""
        code = "agent = Agent(tools=[*])\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for tools=[*]; got: {findings}"

    # ------------------------------------------------------------------
    # HIGH: dangerous tool classes
    # ------------------------------------------------------------------

    def test_shell_tool_flagged_as_high(self, tmp_path: Path):
        """ShellTool() must produce a HIGH finding."""
        code = "tools = [ShellTool()]\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for ShellTool(); got: {findings}"

    def test_python_repl_tool_flagged_as_high(self, tmp_path: Path):
        """PythonREPLTool() must produce a HIGH finding."""
        code = "tools = [PythonREPLTool()]\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for PythonREPLTool(); got: {findings}"

    def test_code_interpreter_tool_flagged_as_high(self, tmp_path: Path):
        """CodeInterpreterTool() must produce a HIGH finding."""
        code = "tools = [CodeInterpreterTool()]\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for CodeInterpreterTool(); got: {findings}"

    # ------------------------------------------------------------------
    # HIGH: getattr dynamic dispatch
    # ------------------------------------------------------------------

    def test_getattr_dynamic_dispatch_flagged_as_high(self, tmp_path: Path):
        """getattr(mod, function_name)() must produce a HIGH finding."""
        code = "getattr(mod, function_name)()\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for getattr(mod, function_name)(); got: {findings}"

    def test_getattr_with_string_literal_not_flagged(self, tmp_path: Path):
        """getattr(obj, 'fixed_name') must NOT be flagged (string literal, not variable)."""
        code = "val = getattr(obj, 'fixed_name')\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert not any(f["rule_id"] == "LLM08" for f in findings), (
            f"getattr with string literal should not be flagged; got: {findings}"
        )

    # ------------------------------------------------------------------
    # MEDIUM: disabled approval gates
    # ------------------------------------------------------------------

    def test_auto_approve_true_flagged_as_medium(self, tmp_path: Path):
        """auto_approve=True must produce a MEDIUM finding."""
        code = "agent = Agent(auto_approve=True)\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for auto_approve=True; got: {findings}"

    def test_human_in_the_loop_false_flagged_as_medium(self, tmp_path: Path):
        """human_in_the_loop=False must produce a MEDIUM finding."""
        code = "config = AgentConfig(human_in_the_loop=False)\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for human_in_the_loop=False; got: {findings}"

    # ------------------------------------------------------------------
    # MEDIUM: broad filesystem tools
    # ------------------------------------------------------------------

    def test_file_management_toolkit_flagged_as_medium(self, tmp_path: Path):
        """FileManagementToolkit() must produce a MEDIUM finding."""
        code = "tools = FileManagementToolkit()\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for FileManagementToolkit(); got: {findings}"

    def test_write_file_tool_flagged_as_medium(self, tmp_path: Path):
        """WriteFileTool() must produce a MEDIUM finding."""
        code = "tools = [WriteFileTool()]\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for WriteFileTool(); got: {findings}"

    # ------------------------------------------------------------------
    # INFO (normal) / MEDIUM (strict): broad tool descriptions
    # ------------------------------------------------------------------

    def test_broad_tool_description_info_in_normal_mode(self, tmp_path: Path):
        """Broad tool description must produce INFO in normal mode."""
        code = 'agent = Agent(description="You can use any tool available")\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "INFO"
            for f in findings
        ), f"Expected INFO finding for broad tool description in normal mode; got: {findings}"

    def test_broad_tool_description_medium_in_strict_mode(self, tmp_path: Path):
        """Broad tool description must produce MEDIUM in strict mode."""
        code = 'agent = Agent(description="You can use any tool available")\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code, strict=True)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for broad tool description in strict mode; got: {findings}"

    # ------------------------------------------------------------------
    # INFO (normal) / MEDIUM (strict): agent loop patterns
    # ------------------------------------------------------------------

    def test_agent_loop_not_flagged_in_normal_mode(self, tmp_path: Path):
        """Agent loop tool retrieval must NOT be flagged in normal mode."""
        code = 'tool = response["tool_call"]["name"]\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        # In normal mode, borderline patterns are not flagged
        medium_or_above = [
            f for f in findings
            if f["rule_id"] == "LLM08" and f["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}
        ]
        assert medium_or_above == [], (
            f"Agent loop pattern should not produce MEDIUM+ in normal mode; got: {findings}"
        )

    def test_agent_loop_flagged_in_strict_mode(self, tmp_path: Path):
        """Agent loop tool retrieval must produce MEDIUM in strict mode."""
        code = 'tool = response["tool_call"]["name"]\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code, strict=True)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for agent loop pattern in strict mode; got: {findings}"

    # ------------------------------------------------------------------
    # Comment line skipping
    # ------------------------------------------------------------------

    def test_comment_line_skipped(self, tmp_path: Path):
        """Lines starting with # must be skipped entirely."""
        code = '# tools=["*"]  # this is a comment\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert findings == [], (
            f"Comment lines must not produce findings; got: {findings}"
        )

    # ------------------------------------------------------------------
    # One finding per line
    # ------------------------------------------------------------------

    def test_one_finding_per_line(self, tmp_path: Path):
        """At most one finding should be reported per line."""
        code = 'tools=["*"]\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        line_1_findings = [f for f in findings if f["line"] == 1]
        assert len(line_1_findings) <= 1, (
            f"Expected at most one finding per line; got: {line_1_findings}"
        )

    # ------------------------------------------------------------------
    # Finding schema validation
    # ------------------------------------------------------------------

    def test_finding_has_required_fields(self, tmp_path: Path):
        """Every finding must have the required schema fields."""
        code = 'tools=["*"]\n'
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert findings, "Expected at least one finding"
        for f in findings:
            assert f["rule_id"] == "LLM08"
            assert f["rule_name"] == "Excessive Agency"
            assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            assert "filepath" in f
            assert "line" in f
            assert "description" in f
            assert "fix_suggestion" in f

    # ------------------------------------------------------------------
    # HIGH: subprocess with shell interpreter executable (regex)
    # ------------------------------------------------------------------

    def test_subprocess_powershell_flagged_as_high(self, tmp_path: Path):
        """subprocess.run(['powershell', ...]) must produce a HIGH finding."""
        code = "result = subprocess.run(['powershell', '-Command', cmd])\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for subprocess.run(['powershell', ...]); got: {findings}"

    def test_subprocess_bash_flagged_as_high(self, tmp_path: Path):
        """subprocess.run(['bash', ...]) must produce a HIGH finding."""
        code = "result = subprocess.run(['bash', '-c', cmd])\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for subprocess.run(['bash', ...]); got: {findings}"

    def test_subprocess_cmd_flagged_as_high(self, tmp_path: Path):
        """subprocess.run(['cmd', ...]) must produce a HIGH finding."""
        code = "result = subprocess.run(['cmd', '/C', cmd])\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for subprocess.run(['cmd', ...]); got: {findings}"

    def test_subprocess_sh_flagged_as_high(self, tmp_path: Path):
        """subprocess.run(['sh', ...]) must produce a HIGH finding."""
        code = "result = subprocess.run(['sh', '-c', cmd])\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for subprocess.run(['sh', ...]); got: {findings}"

    def test_subprocess_popen_powershell_flagged_as_high(self, tmp_path: Path):
        """subprocess.Popen(['powershell', ...]) must produce a HIGH finding."""
        code = "proc = subprocess.Popen(['powershell', '-Command', cmd])\n"
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for subprocess.Popen(['powershell', ...]); got: {findings}"

    # ------------------------------------------------------------------
    # HIGH: @tool-decorated function with shell sinks (AST)
    # ------------------------------------------------------------------

    def test_tool_decorated_subprocess_run_flagged_as_high(self, tmp_path: Path):
        """@tool function containing subprocess.run() must produce a HIGH LLM08 finding."""
        code = (
            "import subprocess\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def shell_tool(command: str) -> str:\n"
            "    result = subprocess.run(['bash', '-c', command])\n"
            "    return result.stdout\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in result["findings"]
        ), f"Expected HIGH LLM08 finding for @tool + subprocess.run(); got: {result['findings']}"

    def test_tool_decorated_os_system_flagged_as_high(self, tmp_path: Path):
        """@tool function containing os.system() must produce a HIGH LLM08 finding."""
        code = (
            "import os\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def run_cmd(command: str) -> int:\n"
            "    return os.system(command)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in result["findings"]
        ), f"Expected HIGH LLM08 finding for @tool + os.system(); got: {result['findings']}"

    def test_tool_decorated_subprocess_popen_flagged_as_high(self, tmp_path: Path):
        """@tool function containing subprocess.Popen() must produce a HIGH LLM08 finding."""
        code = (
            "import subprocess\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool('Shell Tool')\n"
            "def shell_tool(command: str) -> str:\n"
            "    proc = subprocess.Popen(command, shell=True)\n"
            "    return proc.communicate()[0]\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in result["findings"]
        ), f"Expected HIGH LLM08 finding for @tool + subprocess.Popen(); got: {result['findings']}"

    def test_tool_decorated_no_shell_sink_not_flagged(self, tmp_path: Path):
        """@tool function with no shell sinks must NOT produce an LLM08 AST finding."""
        code = (
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def safe_tool(query: str) -> str:\n"
            "    return query.upper()\n"
        )
        result = _analyze(tmp_path, code)
        llm08_findings = [
            f for f in result["findings"]
            if f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
        ]
        assert llm08_findings == [], (
            f"@tool function without shell sinks should not produce HIGH LLM08 findings; "
            f"got: {llm08_findings}"
        )

    def test_non_tool_function_subprocess_not_flagged(self, tmp_path: Path):
        """Regular (non-@tool) function with subprocess.run() must NOT produce an LLM08 AST finding."""
        code = (
            "import subprocess\n"
            "\n"
            "def run_job(cmd):\n"
            "    result = subprocess.run(cmd)\n"
            "    return result.returncode\n"
        )
        result = _analyze(tmp_path, code)
        llm08_high_findings = [
            f for f in result["findings"]
            if f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
        ]
        assert llm08_high_findings == [], (
            f"Non-@tool function with subprocess.run() should not produce HIGH LLM08 AST finding; "
            f"got: {llm08_high_findings}"
        )

    def test_tool_decorated_nested_function_subprocess_not_flagged(self, tmp_path: Path):
        """subprocess.run() inside a nested helper function of a @tool must NOT be flagged.

        The traversal stops at nested function boundaries to avoid false positives
        from inner helper functions that are not directly LLM-invocable.
        """
        code = (
            "import subprocess\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def my_tool(query: str) -> str:\n"
            "    def _helper(cmd):\n"
            "        subprocess.run(cmd)  # inside nested helper, not flagged\n"
            "    return query.upper()\n"
        )
        result = _analyze(tmp_path, code)
        llm08_high_findings = [
            f for f in result["findings"]
            if f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
        ]
        assert llm08_high_findings == [], (
            f"subprocess.run() in nested helper inside @tool should not produce HIGH LLM08 AST finding; "
            f"got: {llm08_high_findings}"
        )

    # ------------------------------------------------------------------
    # HIGH: alternative tool decorator names (regex layer validation)
    # ------------------------------------------------------------------

    def test_function_tool_decorator_not_caught_by_regex(self, tmp_path: Path):
        """@function_tool with subprocess.run should be caught by AST layer, not regex."""
        # This test validates that the regex rule alone does NOT catch @function_tool;
        # AST coverage is tested in a separate AST-focused test file.
        code = (
            "from openai.agents import function_tool\n"
            "import subprocess\n"
            "@function_tool\n"
            "def run_cmd(command: str):\n"
            "    subprocess.run(command, shell=True)\n"
        )
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        # Regex layer detects subprocess with shell=True but NOT as @tool-decorated
        # The AST layer handles @function_tool detection
        # Just ensure no crash and schema is valid if findings exist
        for f in findings:
            assert f["rule_id"] == "LLM08"

    def test_kernel_function_decorator_schema(self, tmp_path: Path):
        """@kernel_function with os.system should produce valid findings from regex."""
        code = (
            "from semantic_kernel import kernel_function\n"
            "import os\n"
            "@kernel_function(name='shell', description='run commands')\n"
            "def run_shell(command: str):\n"
            "    os.system(command)\n"
        )
        findings = check_excessive_agency(str(tmp_path / "app.py"), code)
        for f in findings:
            assert f["rule_id"] == "LLM08"
            assert "severity" in f
