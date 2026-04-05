"""Core scanning engine for LLM Armor."""

import warnings
from pathlib import Path

from llmarmor import ast_analysis as _ast
from llmarmor.rules import get_rules

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".tox",
    "dist",
    "build",
    ".eggs",
}


def run_scan(path: str, strict: bool = False) -> list[dict]:
    """Scan a directory for LLM security vulnerabilities.

    Walks *path* recursively, checks every supported file against all registered
    rules and returns a list of finding dicts.  Each finding contains:

    - ``rule_id``      – OWASP LLM Top 10 rule identifier (e.g. "LLM01")
    - ``rule_name``    – Human-readable rule name
    - ``severity``     – "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INFO"
    - ``filepath``     – Absolute path to the affected file
    - ``line``         – 1-based line number of the finding
    - ``description``  – What was detected and why it is dangerous
    - ``fix_suggestion`` – Recommended remediation

    When *strict* is ``True``, additional borderline patterns are included
    (plain tainted variables in role messages, stricter system-prompt messaging).

    In addition to ``.py`` files, the scanner also checks: ``.env``, ``.yaml``,
    ``.yml``, ``.json``, ``.toml``, ``.js``, ``.ts``, ``.md``, ``.txt``, and
    ``.ipynb`` files using type-specific handlers.
    """
    findings: list[dict] = []
    scan_path = Path(path)

    for file_path in _iter_files(scan_path):
        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        if file_path.suffix == ".py":
            _scan_file(file_path, content, findings, strict=strict)
        else:
            _scan_non_python_file(file_path, content, findings)

    return findings


_EVAL_CONTEXT_DOWNGRADE_RULES = frozenset(["LLM05", "LLM08"])


def _scan_file(py_file: Path, content: str, findings: list[dict], strict: bool = False) -> None:
    """Run all checks on a single Python file and append results to *findings*."""
    # AST analysis: additional findings + (line, rule_id) pairs to suppress.
    # A try/except here ensures that any unexpected error in the AST analysis
    # (beyond SyntaxError, which analyze() handles internally) never silences
    # the regex rules.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            ast_result = _ast.analyze(str(py_file), content, strict=strict)
        ast_findings: list[dict] = ast_result["findings"]
        cleared: set[tuple[int, str]] = ast_result["cleared"]
        is_eval_ctx: bool = ast_result.get("is_eval_context", False)
    except Exception:  # noqa: BLE001
        ast_findings = []
        cleared = set()
        is_eval_ctx = False

    # Regex rules: skip findings on lines that AST has already handled or
    # determined to be safe (e.g. **config with max_tokens, user-role messages).
    seen: set[tuple[str, int, str]] = set()
    for rule_checker in get_rules(strict=strict):
        for finding in rule_checker(py_file, content):
            if (finding["line"], finding["rule_id"]) not in cleared:
                # Downgrade LLM05 and LLM08 regex findings in test/eval files to
                # INFO to reduce noise from legitimate evaluation harnesses.
                if is_eval_ctx and finding["rule_id"] in _EVAL_CONTEXT_DOWNGRADE_RULES:
                    finding = {
                        **finding,
                        "severity": "INFO",
                        "description": f"[eval context] {finding['description']}",
                    }
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


def _scan_non_python_file(
    file_path: Path, content: str, findings: list[dict]
) -> None:
    """Dispatch a non-Python file to the appropriate handler."""
    from llmarmor.handlers import HANDLERS

    # Try suffix first (e.g. ".yaml", ".js"), then fall back to the full name
    # for dotfiles like ".env" whose pathlib suffix is empty.
    handler = HANDLERS.get(file_path.suffix) or HANDLERS.get(file_path.name)
    if handler is None:
        return

    seen: set[tuple[str, int, str]] = set()
    for finding in handler(str(file_path), content):
        key = (finding["filepath"], finding["line"], finding["rule_id"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)


def _iter_files(root: Path):
    """Yield all scannable files under *root*, skipping hidden and noise directories.

    Supported extensions: ``.py``, ``.env``, ``.yaml``, ``.yml``, ``.json``,
    ``.toml``, ``.js``, ``.ts``, ``.md``, ``.txt``, ``.ipynb``.
    """
    from llmarmor.handlers import HANDLERS

    _SUPPORTED_SUFFIXES = frozenset({".py"} | HANDLERS.keys())

    for item in root.iterdir():
        if item.is_dir():
            if item.name.startswith(".") or item.name in _SKIP_DIRS:
                continue
            yield from _iter_files(item)
        elif item.suffix in _SUPPORTED_SUFFIXES or item.name in HANDLERS:
            # item.name check handles dotfiles like ".env" whose pathlib suffix is ""
            yield item


# Keep the old name as an alias for backwards compatibility with any code that
# references it directly (including existing tests).
def _iter_python_files(root: Path):
    """Yield ``.py`` files under *root*.  Deprecated — use :func:`_iter_files`."""
    for item in root.iterdir():
        if item.is_dir():
            if item.name.startswith(".") or item.name in _SKIP_DIRS:
                continue
            yield from _iter_python_files(item)
        elif item.suffix == ".py":
            yield item
