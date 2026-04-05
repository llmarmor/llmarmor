"""Tests for AST-based @tool decorator detection with expanded decorator names."""

from pathlib import Path
import pytest
from llmarmor.ast_analysis import analyze


class TestLLM08ASTToolDecorators:
    """Tests for AST detection of shell sinks inside @tool-decorated functions."""

    def test_function_tool_with_subprocess(self, tmp_path: Path):
        """@function_tool (OpenAI Agents SDK) with subprocess.run → HIGH LLM08."""
        code = (
            "import subprocess\n"
            "@function_tool\n"
            "def run_cmd(command: str):\n"
            "    subprocess.run(command, shell=True)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH LLM08 finding for @function_tool + subprocess.run; got: {findings}"

    def test_kernel_function_with_os_system(self, tmp_path: Path):
        """@kernel_function (Semantic Kernel) with os.system → HIGH LLM08."""
        code = (
            "import os\n"
            "@kernel_function(name='shell', description='run commands')\n"
            "def run_shell(command: str):\n"
            "    os.system(command)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH LLM08 finding for @kernel_function + os.system; got: {findings}"

    def test_ai_tool_with_subprocess(self, tmp_path: Path):
        """@ai_tool (Pydantic AI) with subprocess.Popen → HIGH LLM08."""
        code = (
            "import subprocess\n"
            "@ai_tool\n"
            "def exec_cmd(cmd: str):\n"
            "    subprocess.Popen(cmd, shell=True)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH LLM08 finding for @ai_tool + subprocess.Popen; got: {findings}"

    def test_ai_fn_with_os_popen(self, tmp_path: Path):
        """@ai_fn (Marvin AI) with os.popen → HIGH LLM08."""
        code = (
            "import os\n"
            "@ai_fn\n"
            "def run(command: str):\n"
            "    os.popen(command)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH LLM08 finding for @ai_fn + os.popen; got: {findings}"

    def test_module_qualified_tool_decorator(self, tmp_path: Path):
        """@module.tool(...) form with subprocess.run → HIGH LLM08."""
        code = (
            "import subprocess\n"
            "import langchain\n"
            "@langchain.tool('Shell Tool')\n"
            "def shell(command: str):\n"
            "    subprocess.run(command, shell=True)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH LLM08 finding for @module.tool + subprocess.run; got: {findings}"

    def test_original_tool_decorator_still_works(self, tmp_path: Path):
        """Ensure existing @tool detection is not broken."""
        code = (
            "import subprocess\n"
            "@tool('Shell Tool', args_schema=Shell)\n"
            "def shell_tool(command: str):\n"
            "    subprocess.run(['powershell', '-Command'] + command.split(), capture_output=True)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        assert any(
            f["rule_id"] == "LLM08" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH LLM08 finding for @tool + subprocess.run; got: {findings}"

    def test_non_tool_decorator_not_flagged(self, tmp_path: Path):
        """A function with @app.route (not a tool decorator) should NOT produce LLM08."""
        code = (
            "import subprocess\n"
            "@app.route('/run')\n"
            "def run_cmd(command: str):\n"
            "    subprocess.run(command, shell=True)\n"
        )
        result = analyze(str(tmp_path / "app.py"), code)
        findings = result["findings"]
        llm08_tool_findings = [
            f for f in findings
            if f["rule_id"] == "LLM08" and "@tool-decorated" in f.get("description", "")
        ]
        assert llm08_tool_findings == [], (
            f"Non-tool decorator should not produce @tool LLM08 finding; got: {llm08_tool_findings}"
        )
