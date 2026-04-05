"""Core scanning engine for LLM Armor."""

import fnmatch
import re
import warnings
from pathlib import Path
from typing import Optional

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

# Inline suppression comment pattern.
# Matches: # llmarmor: ignore  OR  # llmarmor: ignore[LLM01,LLM05]
_INLINE_SUPPRESS_RE = re.compile(
    r"#\s*llmarmor\s*:\s*ignore(?:\[([^\]]*)\])?",
    re.IGNORECASE,
)

_LLMARMORIGNORE_FILENAME = ".llmarmorignore"


def _load_ignore_patterns(root: Path) -> list[str]:
    """Read glob patterns from *root*/.llmarmorignore (gitignore-style).

    Lines starting with ``#`` and blank lines are ignored.
    """
    ignore_file = root / _LLMARMORIGNORE_FILENAME
    if not ignore_file.exists():
        return []
    patterns: list[str] = []
    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped)
    return patterns


def _is_ignored(file_path: Path, root: Path, patterns: list[str]) -> bool:
    """Return ``True`` if *file_path* matches any ignore pattern relative to *root*."""
    try:
        rel = file_path.relative_to(root).as_posix()
    except ValueError:
        rel = file_path.as_posix()

    for pattern in patterns:
        # Match against the relative path (supports path separators) and
        # against the bare file name (supports simple name patterns).
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(file_path.name, pattern):
            return True
    return False


def _is_suppressed(lines: list[str], line_num: int, rule_id: str) -> bool:
    """Return ``True`` if a finding at *line_num* carries an inline suppression comment.

    Checks both the finding's own line and the line immediately above it (to
    support placing the comment on the line before the flagged code).

    :param lines: Zero-indexed list of source lines (``content.splitlines()``).
    :param line_num: 1-based line number of the finding.
    :param rule_id: Rule identifier to check (e.g. ``"LLM01"``).
    """
    for idx in (line_num - 1, line_num - 2):
        if 0 <= idx < len(lines):
            m = _INLINE_SUPPRESS_RE.search(lines[idx])
            if m:
                rule_filter = m.group(1)
                if rule_filter is None:
                    # Bare ``# llmarmor: ignore`` suppresses all rules.
                    return True
                # ``# llmarmor: ignore[LLM01,LLM05]`` — check comma-separated list.
                suppressed_rules = {r.strip().upper() for r in rule_filter.split(",")}
                if rule_id.upper() in suppressed_rules:
                    return True
    return False


def run_scan(path: str, strict: bool = False, config: "Optional[object]" = None) -> list[dict]:
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

    When *config* is a :class:`~llmarmor.config.LLMArmorConfig` instance, its
    ``exclude_paths``, ``rules`` enable/disable flags, and severity overrides
    are applied on top of the scan results.

    In addition to ``.py`` files, the scanner also checks: ``.env``, ``.yaml``,
    ``.yml``, ``.json``, ``.toml``, ``.js``, ``.ts``, ``.md``, ``.txt``, and
    ``.ipynb`` files using type-specific handlers.
    """
    findings: list[dict] = []
    scan_path = Path(path)
    ignore_patterns = _load_ignore_patterns(scan_path)

    # Merge config-level exclude_paths into the ignore pattern list.
    if config is not None and hasattr(config, "exclude_paths"):
        ignore_patterns.extend(config.exclude_paths)

    for file_path in _iter_files(scan_path):
        if _is_ignored(file_path, scan_path, ignore_patterns):
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        if file_path.suffix == ".py":
            _scan_file(file_path, content, findings, strict=strict)
        else:
            _scan_non_python_file(file_path, content, findings)

    # Apply config-level rule filters and severity overrides.
    if config is not None:
        findings = _apply_config(findings, config)

    return findings


def _apply_config(findings: list[dict], config: object) -> list[dict]:
    """Apply rule enable/disable and severity overrides from *config*."""
    result: list[dict] = []
    for f in findings:
        rule_id = f["rule_id"]
        if not config.is_rule_enabled(rule_id):  # type: ignore[attr-defined]
            continue
        override = config.rule_severity_override(rule_id)  # type: ignore[attr-defined]
        if override:
            f = {**f, "severity": override}
        result.append(f)
    return result


_EVAL_CONTEXT_DOWNGRADE_RULES = frozenset(["LLM05", "LLM08"])


def _scan_file(py_file: Path, content: str, findings: list[dict], strict: bool = False) -> None:
    """Run all checks on a single Python file and append results to *findings*."""
    lines = content.splitlines()

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
            line_num = finding["line"]
            rule_id = finding["rule_id"]
            if (line_num, rule_id) in cleared:
                continue
            # Inline suppression check.
            if _is_suppressed(lines, line_num, rule_id):
                continue
            # Downgrade LLM05 and LLM08 regex findings in test/eval files to
            # INFO to reduce noise from legitimate evaluation harnesses.
            if is_eval_ctx and rule_id in _EVAL_CONTEXT_DOWNGRADE_RULES:
                finding = {
                    **finding,
                    "severity": "INFO",
                    "description": f"[eval context] {finding['description']}",
                }
            key = (finding["filepath"], line_num, rule_id)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    # AST-specific findings (aliased variables, role-aware dicts, join, etc.).
    # Deduplicate against any regex findings already collected.
    for finding in ast_findings:
        line_num = finding["line"]
        rule_id = finding["rule_id"]
        # Inline suppression check for AST findings.
        if _is_suppressed(lines, line_num, rule_id):
            continue
        key = (finding["filepath"], line_num, rule_id)
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
