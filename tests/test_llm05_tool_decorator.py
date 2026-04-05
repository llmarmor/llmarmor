"""Tests for LLM05 detection inside ``@tool``-decorated functions.

Parameters of ``@tool``-decorated functions (LangChain, CrewAI, or any
framework using ``@tool``) are chosen by the LLM at runtime and are
therefore treated as source-tainted.  The AST analysis should emit LLM05
findings when those parameters reach dangerous sinks.

Also covers the expanded set of tool decorator names:

* ``@function_tool``  — OpenAI Agents SDK
* ``@kernel_function`` — Microsoft Semantic Kernel
* ``@ai_tool``        — Pydantic AI
* ``@ai_fn``          — Marvin AI
* ``@module.tool(...)`` — module-qualified import form
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


class TestLLM05ExpandedToolDecorators:
    """LLM05 findings for the expanded set of tool decorator names.

    All names in ``_TOOL_DECORATOR_NAMES`` must promote their function
    parameters to ``_source_tainted`` so that LLM05 shell/exec/HTML/
    json.loads checks fire — just like ``@tool`` does.
    """

    # ------------------------------------------------------------------
    # @function_tool  (OpenAI Agents SDK)
    # ------------------------------------------------------------------

    def test_function_tool_subprocess_run_flagged_llm05_critical(self, tmp_path: Path):
        """@function_tool param reaching subprocess.run() → LLM05 CRITICAL."""
        code = (
            "import subprocess\n"
            "@function_tool\n"
            "def run_cmd(command: str) -> str:\n"
            "    return subprocess.run(command, shell=True).stdout\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @function_tool + subprocess.run; got: {result['findings']}"

    def test_function_tool_eval_flagged_llm05_critical(self, tmp_path: Path):
        """@function_tool param reaching eval() → LLM05 CRITICAL."""
        code = (
            "@function_tool\n"
            "def code_runner(expression: str) -> object:\n"
            "    return eval(expression)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @function_tool + eval; got: {result['findings']}"

    # ------------------------------------------------------------------
    # @kernel_function  (Microsoft Semantic Kernel)
    # ------------------------------------------------------------------

    def test_kernel_function_os_system_flagged_llm05_critical(self, tmp_path: Path):
        """@kernel_function param reaching os.system() → LLM05 CRITICAL."""
        code = (
            "import os\n"
            "@kernel_function(name='shell', description='run commands')\n"
            "def run_shell(command: str) -> int:\n"
            "    return os.system(command)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @kernel_function + os.system; got: {result['findings']}"

    def test_kernel_function_exec_flagged_llm05_critical(self, tmp_path: Path):
        """@kernel_function param reaching exec() → LLM05 CRITICAL."""
        code = (
            "@kernel_function\n"
            "def exec_tool(code: str) -> None:\n"
            "    exec(code)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @kernel_function + exec; got: {result['findings']}"

    # ------------------------------------------------------------------
    # @ai_tool  (Pydantic AI)
    # ------------------------------------------------------------------

    def test_ai_tool_subprocess_popen_flagged_llm05_critical(self, tmp_path: Path):
        """@ai_tool param reaching subprocess.Popen() → LLM05 CRITICAL."""
        code = (
            "import subprocess\n"
            "@ai_tool\n"
            "def exec_cmd(cmd: str) -> str:\n"
            "    proc = subprocess.Popen(cmd, shell=True)\n"
            "    return proc.communicate()[0]\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @ai_tool + subprocess.Popen; got: {result['findings']}"

    def test_ai_tool_markup_flagged_llm05_high(self, tmp_path: Path):
        """@ai_tool param reaching Markup() → LLM05 HIGH."""
        code = (
            "from markupsafe import Markup\n"
            "@ai_tool\n"
            "def render(content: str) -> str:\n"
            "    return str(Markup(content))\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in result["findings"]
        ), f"Expected LLM05 HIGH for @ai_tool + Markup; got: {result['findings']}"

    # ------------------------------------------------------------------
    # @ai_fn  (Marvin AI)
    # ------------------------------------------------------------------

    def test_ai_fn_os_popen_flagged_llm05_critical(self, tmp_path: Path):
        """@ai_fn param reaching os.popen() → LLM05 CRITICAL."""
        code = (
            "import os\n"
            "@ai_fn\n"
            "def run(command: str) -> str:\n"
            "    return os.popen(command).read()\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @ai_fn + os.popen; got: {result['findings']}"

    def test_ai_fn_json_loads_flagged_llm05_info(self, tmp_path: Path):
        """@ai_fn param reaching json.loads() → LLM05 INFO in normal mode."""
        code = (
            "import json\n"
            "@ai_fn\n"
            "def parse(data: str) -> dict:\n"
            "    return json.loads(data)\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "INFO"
            for f in result["findings"]
        ), f"Expected LLM05 INFO for @ai_fn + json.loads; got: {result['findings']}"

    # ------------------------------------------------------------------
    # module-qualified form  @module.tool(...)
    # ------------------------------------------------------------------

    def test_module_qualified_tool_subprocess_run_flagged_llm05_critical(self, tmp_path: Path):
        """@module.tool('...') param reaching subprocess.run() → LLM05 CRITICAL."""
        code = (
            "import subprocess\n"
            "import langchain\n"
            "@langchain.tool('Shell Tool')\n"
            "def shell(command: str) -> str:\n"
            "    return subprocess.run(command, shell=True).stdout\n"
        )
        result = _analyze(tmp_path, code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in result["findings"]
        ), f"Expected LLM05 CRITICAL for @module.tool + subprocess.run; got: {result['findings']}"
