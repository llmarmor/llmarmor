"""Core scanning engine for LLM Armor."""

from pathlib import Path

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

        for rule_checker in ALL_RULES:
            findings.extend(rule_checker(py_file, content))

    return findings


def _iter_python_files(root: Path):
    """Yield ``.py`` files under *root*, skipping hidden dirs and known noise dirs."""
    for item in root.iterdir():
        if item.is_dir():
            if item.name.startswith(".") or item.name in _SKIP_DIRS:
                continue
            yield from _iter_python_files(item)
        elif item.suffix == ".py":
            yield item
