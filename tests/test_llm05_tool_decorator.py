"""Tests for LLM05 detection inside ``@tool``-decorated functions.

Parameters of ``@tool``-decorated functions (LangChain, CrewAI, or any
framework using ``@tool``) are chosen by the LLM at runtime and are
therefore treated as source-tainted.  The AST analysis should emit LLM05
findings when those parameters reach dangerous sinks.
"""

from pathlib import Path

import pytest

from llmarmor.ast_analysis import analyze


def _analyze(tmp_path: Path, code: str, filename: str = "app.py") -> dict:
    """Helper that runs AST-based analysis via the public ``analyze()`` entry point."""
    return analyze(str(tmp_path / filename), code)


class TestLLM05ToolDecorator:
    """LLM05 findings from @tool-decorated function parameters."""

    # ------------------------------------------------------------------
    # CRITICAL: shell sinks
    # ------------------------------------------------------------------

    def test_tool_subprocess_run_flagged_llm05_critical(self, tmp_path: Path):
        """@tool function passing param to subprocess.run() → LLM05 CRITICAL."""
        code = (
            "from langchain.tools import tool\n"
            "import subprocess\n"
            "\n"
            "@tool\n"
            "def shell_tool(command: str) -> str:\n"
            "    result = subprocess.run(command, shell=True)\n"
            "    return result.stdout\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool + subprocess.run(); got: {result['findings']}"

    def test_tool_os_system_flagged_llm05_critical(self, tmp_path: Path):
        """@tool function passing param to os.system() → LLM05 CRITICAL."""
        code = (
            "from langchain.tools import tool\n"
            "import os\n"
            "\n"
            "@tool\n"
            "def run_cmd(command: str) -> int:\n"
            "    return os.system(command)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool + os.system(); got: {result['findings']}"

    def test_tool_subprocess_popen_flagged_llm05_critical(self, tmp_path: Path):
        """@tool function passing param to subprocess.Popen() → LLM05 CRITICAL."""
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
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool + subprocess.Popen(); got: {result['findings']}"

    # ------------------------------------------------------------------
    # CRITICAL: exec sinks
    # ------------------------------------------------------------------

    def test_tool_eval_flagged_llm05_critical(self, tmp_path: Path):
        """@tool function passing param to eval() → LLM05 CRITICAL."""
        code = (
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def code_runner(expression: str) -> object:\n"
            "    return eval(expression)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool + eval(); got: {result['findings']}"

    def test_tool_exec_flagged_llm05_critical(self, tmp_path: Path):
        """@tool function passing param to exec() → LLM05 CRITICAL."""
        code = (
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def exec_tool(code: str) -> None:\n"
            "    exec(code)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool + exec(); got: {result['findings']}"

    # ------------------------------------------------------------------
    # HIGH: HTML/XSS sinks
    # ------------------------------------------------------------------

    def test_tool_markup_flagged_llm05_high(self, tmp_path: Path):
        """@tool function passing param to Markup() → LLM05 HIGH."""
        code = (
            "from markupsafe import Markup\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def render_tool(content: str) -> str:\n"
            "    return str(Markup(content))\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in result["findings"]
        ), f"Expected LLM05 HIGH for @tool + Markup(); got: {result['findings']}"

    # ------------------------------------------------------------------
    # INFO (normal) / MEDIUM (strict): json.loads sink
    # ------------------------------------------------------------------

    def test_tool_json_loads_flagged_llm05_info(self, tmp_path: Path):
        """@tool function passing param to json.loads() → LLM05 INFO in normal mode."""
        code = (
            "import json\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def parse_tool(data: str) -> dict:\n"
            "    return json.loads(data)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "INFO"
            for f in result["findings"]
        ), f"Expected LLM05 INFO for @tool + json.loads(); got: {result['findings']}"

    # ------------------------------------------------------------------
    # No finding: safe tool
    # ------------------------------------------------------------------

    def test_tool_no_dangerous_sink_no_llm05(self, tmp_path: Path):
        """@tool function with no dangerous sinks must NOT produce an LLM05 finding."""
        code = (
            "from langchain.tools import tool\n"
            "\n"
            "@tool\n"
            "def safe_tool(query: str) -> str:\n"
            "    return query.upper()\n"
        )
        result = _analyze(tmp_path, code)
        llm05_findings = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05_findings == [], (
            f"@tool function without dangerous sinks should not produce LLM05 findings; "
            f"got: {llm05_findings}"
        )

    # ------------------------------------------------------------------
    # Existing behaviour preserved: non-@tool function params NOT source-tainted
    # ------------------------------------------------------------------

    def test_non_tool_subprocess_run_no_llm05(self, tmp_path: Path):
        """Regular (non-@tool) function with subprocess.run(param) must NOT produce LLM05."""
        code = (
            "import subprocess\n"
            "\n"
            "def run_job(cmd):\n"
            "    result = subprocess.run(cmd)\n"
            "    return result.returncode\n"
        )
        result = _analyze(tmp_path, code)
        llm05_findings = [f for f in result["findings"] if f["rule_id"] == "LLM05"]
        assert llm05_findings == [], (
            f"Non-@tool function with subprocess.run(param) should not produce LLM05 (avoids "
            f"false positives in utility functions); got: {llm05_findings}"
        )

    # ------------------------------------------------------------------
    # Decorator form variations
    # ------------------------------------------------------------------

    def test_tool_called_form_flagged(self, tmp_path: Path):
        """@tool('Tool Name') called-decorator form triggers the same detection."""
        code = (
            "import subprocess\n"
            "from langchain.tools import tool\n"
            "\n"
            "@tool('Shell Exec')\n"
            "def shell_exec(command: str) -> str:\n"
            "    return subprocess.run(command, shell=True).stdout\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool('...') form; got: {result['findings']}"

    def test_tool_with_args_schema_flagged(self, tmp_path: Path):
        """@tool('Name', args_schema=Schema) form triggers the same detection."""
        code = (
            "import subprocess\n"
            "from langchain.tools import tool\n"
            "from pydantic import BaseModel\n"
            "\n"
            "class ShellInput(BaseModel):\n"
            "    command: str\n"
            "\n"
            "@tool('Shell Tool', args_schema=ShellInput)\n"
            "def shell_tool(command: str) -> str:\n"
            "    return subprocess.run(command, shell=True).stdout\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @tool('Name', args_schema=...) form; got: {result['findings']}"
