"""Core scanning engine for LLM Armor."""

import warnings
from pathlib import Path

from llmarmor import ast_analysis as _ast
from llmarmor.rules import ALL_RULES

_SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules"}


def run_scan(path: str) -> list[dict]:
    """Scan a directory for LLM security vulnerabilities.

    Walks *path* recursively, checks every ``.py`` file against all registered
    rules and returns a list of finding dicts.  Each finding contains:

    - ``rule_id``      – OWASP LLM Top 10 rule identifier (e.g. "LLM01")
    - ``rule_name``    – Human-readable rule name
    - ``severity``     – "CRITICAL", "HIGH", or "MEDIUM"
    - ``filepath``     – Absolute path to the affected file
    - ``line``         – 1-based line number of the finding
    - ``description``  – What was detected and why it is dangerous
    - ``fix_suggestion`` – Recommended remediation
    """
    findings: list[dict] = []
    scan_path = Path(path)

    for py_file in _iter_python_files(scan_path):
        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        _scan_file(py_file, content, findings)

    return findings


def _scan_file(py_file: Path, content: str, findings: list[dict]) -> None:
    """Run all checks on a single file and append results to *findings*."""
    # AST analysis: additional findings + (line, rule_id) pairs to suppress.
    # A try/except here ensures that any unexpected error in the AST analysis
    # (beyond SyntaxError, which analyze() handles internally) never silences
    # the regex rules.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            ast_result = _ast.analyze(str(py_file), content)
        ast_findings: list[dict] = ast_result["findings"]
        cleared: set[tuple[int, str]] = ast_result["cleared"]
    except Exception:  # noqa: BLE001
        ast_findings = []
        cleared = set()

    # Regex rules: skip findings on lines that AST has already handled or
    # determined to be safe (e.g. **config with max_tokens, user-role messages).
    seen: set[tuple[str, int, str]] = set()
    for rule_checker in ALL_RULES:
        for finding in rule_checker(py_file, content):
            if (finding["line"], finding["rule_id"]) not in cleared:
                key = (finding["filepath"], finding["line"], finding["rule_id"])
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)

    # AST-specific findings (aliased variables, role-aware dicts, join, etc.).
    # Deduplicate against any regex findings already collected.
    for finding in ast_findings:
        key = (finding["filepath"], finding["line"], finding["rule_id"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)


def _iter_python_files(root: Path):
    """Yield ``.py`` files under *root*, skipping hidden dirs and known noise dirs."""
    for item in root.iterdir():
        if item.is_dir():
            if item.name.startswith(".") or item.name in _SKIP_DIRS:
                continue
            yield from _iter_python_files(item)
        elif item.suffix == ".py":
            yield item
