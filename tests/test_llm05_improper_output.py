"""Tests for LLM05: Improper Output Handling — regex rule."""

from pathlib import Path

import pytest

from llmarmor.rules.llm05_improper_output import check_improper_output


class TestLLM05ImproperOutput:
    """Tests for the check_improper_output regex rule."""

    # ------------------------------------------------------------------
    # CRITICAL: eval / exec / compile
    # ------------------------------------------------------------------

    def test_eval_with_llm_response_variable(self, tmp_path: Path):
        """eval(ai_response) must produce a CRITICAL finding."""
        code = "result = eval(ai_response)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for eval(ai_response); got: {findings}"

    def test_exec_with_llm_output_variable(self, tmp_path: Path):
        """exec(llm_output) must produce a CRITICAL finding."""
        code = "exec(llm_output)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for exec(llm_output); got: {findings}"

    def test_compile_with_model_response(self, tmp_path: Path):
        """compile(model_response, ...) must produce a CRITICAL finding."""
        code = 'code_obj = compile(model_response, "<string>", "exec")\n'
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for compile(model_response); got: {findings}"

    # ------------------------------------------------------------------
    # CRITICAL: shell / subprocess sinks
    # ------------------------------------------------------------------

    def test_subprocess_run_with_llm_output(self, tmp_path: Path):
        """subprocess.run(llm_output) must produce a CRITICAL finding."""
        code = "subprocess.run(llm_output, shell=True)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for subprocess.run(llm_output); got: {findings}"

    def test_os_system_with_ai_response(self, tmp_path: Path):
        """os.system(ai_response) must produce a CRITICAL finding."""
        code = "os.system(ai_response)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "CRITICAL"
            for f in findings
        ), f"Expected CRITICAL finding for os.system(ai_response); got: {findings}"

    # ------------------------------------------------------------------
    # HIGH: SQL injection
    # ------------------------------------------------------------------

    def test_sql_fstring_with_model_response(self, tmp_path: Path):
        """cursor.execute(f-string with LLM variable) must produce a HIGH finding."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {model_response}")\n'
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for SQL fstring with model_response; got: {findings}"

    def test_sql_fstring_with_llm_text(self, tmp_path: Path):
        """cursor.execute(f-string with llm_text) must produce a HIGH finding."""
        code = 'cursor.execute(f"SELECT * FROM t WHERE val = \'{llm_text}\'")\n'
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for SQL fstring with llm_text; got: {findings}"

    # ------------------------------------------------------------------
    # HIGH: HTML / XSS sinks
    # ------------------------------------------------------------------

    def test_markup_with_chat_output(self, tmp_path: Path):
        """Markup(chat_output) must produce a HIGH finding."""
        code = "html = Markup(chat_output)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for Markup(chat_output); got: {findings}"

    def test_render_template_string_with_llm_content(self, tmp_path: Path):
        """render_template_string(llm_content) must produce a HIGH finding."""
        code = "render_template_string(llm_content)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for render_template_string(llm_content); got: {findings}"

    def test_mark_safe_with_ai_message(self, tmp_path: Path):
        """mark_safe(ai_message) must produce a HIGH finding."""
        code = "safe_html = mark_safe(ai_message)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "HIGH"
            for f in findings
        ), f"Expected HIGH finding for mark_safe(ai_message); got: {findings}"

    # ------------------------------------------------------------------
    # INFO (normal) / MEDIUM (strict): json.loads
    # ------------------------------------------------------------------

    def test_json_loads_with_llm_output_normal_mode(self, tmp_path: Path):
        """json.loads(completion_text) must produce INFO in normal mode."""
        code = "data = json.loads(completion_text)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "INFO"
            for f in findings
        ), f"Expected INFO finding for json.loads(completion_text) in normal mode; got: {findings}"

    def test_json_loads_with_llm_output_strict_mode(self, tmp_path: Path):
        """json.loads(completion_text) must produce MEDIUM in strict mode."""
        code = "data = json.loads(completion_text)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code, strict=True)
        assert any(
            f["rule_id"] == "LLM05" and f["severity"] == "MEDIUM"
            for f in findings
        ), f"Expected MEDIUM finding for json.loads(completion_text) in strict mode; got: {findings}"

    def test_json_loads_with_gpt_response(self, tmp_path: Path):
        """json.loads(gpt_response) must be flagged."""
        code = "parsed = json.loads(gpt_response)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert any(f["rule_id"] == "LLM05" for f in findings), (
            f"Expected LLM05 finding for json.loads(gpt_response); got: {findings}"
        )

    # ------------------------------------------------------------------
    # False-positive prevention: generic variables without LLM context
    # ------------------------------------------------------------------

    def test_no_finding_for_generic_result_variable(self, tmp_path: Path):
        """eval(result) where result has no LLM context must NOT be flagged."""
        code = "output = eval(result)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert findings == [], (
            f"Generic 'result' variable should not trigger LLM05; got: {findings}"
        )

    def test_no_finding_for_generic_data_variable(self, tmp_path: Path):
        """subprocess.run(data) where data has no LLM context must NOT be flagged."""
        code = "subprocess.run(data, shell=True)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert findings == [], (
            f"Generic 'data' variable should not trigger LLM05; got: {findings}"
        )

    def test_no_finding_for_generic_json_variable(self, tmp_path: Path):
        """json.loads(payload) where payload has no LLM context must NOT be flagged."""
        code = "obj = json.loads(payload)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert findings == [], (
            f"Generic 'payload' variable should not trigger LLM05; got: {findings}"
        )

    # ------------------------------------------------------------------
    # Comment line skipping
    # ------------------------------------------------------------------

    def test_comment_line_skipped(self, tmp_path: Path):
        """Lines starting with # must be skipped entirely."""
        code = "# eval(ai_response)  # this is just a comment\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert findings == [], (
            f"Comment lines must not produce findings; got: {findings}"
        )

    # ------------------------------------------------------------------
    # One finding per line
    # ------------------------------------------------------------------

    def test_one_finding_per_line(self, tmp_path: Path):
        """At most one finding should be reported per line."""
        code = "eval(llm_output)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        line_1_findings = [f for f in findings if f["line"] == 1]
        assert len(line_1_findings) <= 1, (
            f"Expected at most one finding per line; got: {line_1_findings}"
        )

    # ------------------------------------------------------------------
    # Finding schema validation
    # ------------------------------------------------------------------

    def test_finding_has_required_fields(self, tmp_path: Path):
        """Every finding must have the required schema fields."""
        code = "eval(ai_response)\n"
        findings = check_improper_output(str(tmp_path / "app.py"), code)
        assert findings, "Expected at least one finding"
        for f in findings:
            assert f["rule_id"] == "LLM05"
            assert f["rule_name"] == "Improper Output Handling"
            assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            assert "filepath" in f
            assert "line" in f
            assert "description" in f
            assert "fix_suggestion" in f
