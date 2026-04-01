"""Output formatters for LLM Armor scan results.

Supported formats:
- ``grouped`` (default): findings grouped by rule, one section per rule
- ``flat``: one line per finding (legacy format)
- ``json``: grouped JSON with ``meta`` and ``findings`` blocks
- ``md`` / ``markdown``: Markdown report
"""

import json
import os
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from typing import Sequence

from rich.console import Console
from rich.table import Table

from llmarmor import __version__

# ---------------------------------------------------------------------------
# Path truncation helper
# ---------------------------------------------------------------------------

_DEFAULT_MAX_PATH_WIDTH = 80


def _terminal_width() -> int:
    """Return the terminal width, falling back to 120."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:  # noqa: BLE001
        return 120


def truncate_path(path: str, max_width: int | None = None) -> str:
    """Truncate *path* to at most *max_width* characters.

    If truncation is needed, characters are removed from the **middle** of the
    path so that the filename at the end is always preserved.  The removed
    section is replaced with ``...``.

    Examples::

        truncate_path("a/b/c/d/e/f.py", max_width=15)  →  "a/.../e/f.py"
        truncate_path("short.py", max_width=80)          →  "short.py"
    """
    if max_width is None:
        max_width = _DEFAULT_MAX_PATH_WIDTH

    if len(path) <= max_width:
        return path

    # Ensure we always show the filename at the end.
    # We keep as many characters from the *end* as possible (up to half
    # max_width minus ellipsis overhead), and fill the rest from the start.
    ellipsis = "..."
    ellipsis_len = len(ellipsis)

    # Reserve space: allocate two-thirds to the tail so the filename (at the end)
    # is always visible, and one-third to the head for path context.
    available = max_width - ellipsis_len
    tail_len = min(available * 2 // 3, len(path))
    head_len = available - tail_len

    # Adjust: if head_len is 0, show at least one character of context.
    if head_len < 0:
        head_len = 0

    return path[:head_len] + ellipsis + path[len(path) - tail_len :]


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _severity_sort_key(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(_SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Grouped format (default)
# ---------------------------------------------------------------------------

_RULE_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM10": "Unbounded Consumption",
}


def format_grouped(findings: Sequence[dict], console: Console, scan_path: str) -> None:
    """Print findings grouped by rule to *console* (default format)."""
    if not findings:
        console.print("[green]✅ No vulnerabilities detected.[/green]")
        return

    # Group findings: rule_id → list[dict]
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_rule[f["rule_id"]].append(f)

    # Sort rule groups by worst severity first.
    def _group_severity(rule_id: str) -> int:
        group = by_rule[rule_id]
        return min(_severity_sort_key(f["severity"]) for f in group)

    sorted_rules = sorted(by_rule.keys(), key=_group_severity)

    for rule_id in sorted_rules:
        group = by_rule[rule_id]
        # Use the severity of the worst finding in the group for the header.
        worst_sev = min(group, key=lambda f: _severity_sort_key(f["severity"]))["severity"]
        color = _SEVERITY_COLORS.get(worst_sev, "white")
        rule_name = group[0].get("rule_name") or _RULE_NAMES.get(rule_id, rule_id)

        console.print(
            f"\n[bold]━━━ {rule_id}: {rule_name} ([{color}]{worst_sev}[/{color}]) ━━━[/bold]"
        )

        # Deduplicate descriptions (should all be the same per rule in practice).
        description = group[0].get("description", "")
        if description:
            console.print(f"{description}\n")

        # Locations
        for f in sorted(group, key=lambda x: (x["filepath"], x["line"])):
            fp = truncate_path(f["filepath"])
            console.print(f"  [cyan]→[/cyan] {fp}:{f['line']}")

        # Fix suggestion (first non-empty one).
        fix = next((f.get("fix_suggestion") for f in group if f.get("fix_suggestion")), None)
        if fix:
            console.print(f"\n[dim]Fix: {fix}[/dim]")

    # Summary line
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    parts = [f"{sev_counts[s]} {s}" for s in _SEVERITY_ORDER if s in sev_counts]
    console.print(f"\n[bold]Summary: {len(findings)} finding(s) ({', '.join(parts)})[/bold]")


# ---------------------------------------------------------------------------
# Flat format (legacy, one line per finding)
# ---------------------------------------------------------------------------

def format_flat(findings: Sequence[dict], console: Console, scan_path: str) -> None:
    """Print one finding per line, grouped by severity (legacy format)."""
    if not findings:
        console.print("[green]✅ No vulnerabilities detected.[/green]")
        return

    for severity in _SEVERITY_ORDER:
        group = [f for f in findings if f["severity"] == severity]
        if not group:
            continue

        color = _SEVERITY_COLORS[severity]
        table = Table(
            title=f"[{color}]{severity}[/{color}] — {len(group)} finding(s)",
            show_lines=True,
        )
        table.add_column("Rule", style="bold", width=8)
        table.add_column("File", no_wrap=False)
        table.add_column("Line", width=6)
        table.add_column("Description")

        for f in group:
            table.add_row(
                f["rule_id"],
                truncate_path(f["filepath"]),
                str(f["line"]),
                f["description"],
            )

        console.print(table)

    # Summary panel
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    parts = [f"{sev_counts[s]} {s}" for s in _SEVERITY_ORDER if s in sev_counts]
    console.print(f"\n[bold]Summary: {len(findings)} finding(s) ({', '.join(parts)})[/bold]")


# ---------------------------------------------------------------------------
# JSON format
# ---------------------------------------------------------------------------

def _build_summary(findings: Sequence[dict]) -> dict:
    """Return a severity-count summary dict for *findings*."""
    counts: dict[str, int] = {s.lower(): 0 for s in _SEVERITY_ORDER}
    for f in findings:
        key = f["severity"].lower()
        counts[key] = counts.get(key, 0) + 1
    counts["total"] = len(findings)
    return counts


def _group_findings(findings: Sequence[dict]) -> list[dict]:
    """Group flat findings by (rule_id, severity, description) → locations list."""
    groups: dict[tuple, dict] = {}
    for f in findings:
        key = (f["rule_id"], f["severity"], f.get("description", ""))
        if key not in groups:
            groups[key] = {
                "rule_id": f["rule_id"],
                "rule_name": f.get("rule_name") or _RULE_NAMES.get(f["rule_id"], f["rule_id"]),
                "severity": f["severity"],
                "description": f.get("description", ""),
                "fix_suggestion": f.get("fix_suggestion", ""),
                "locations": [],
            }
        groups[key]["locations"].append(
            {"filepath": f.get("filepath", ""), "line": f.get("line", 0)}
        )

    # Sort groups by severity then rule_id.
    return sorted(
        groups.values(),
        key=lambda g: (_severity_sort_key(g["severity"]), g["rule_id"]),
    )


def format_json(
    findings: Sequence[dict],
    console: Console,
    scan_path: str,
    mode: str = "normal",
) -> None:
    """Print findings as a grouped JSON object with a ``meta`` block to stdout."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output = {
        "meta": {
            "tool": "llmarmor",
            "version": __version__,
            "scanned_path": scan_path,
            "timestamp": timestamp,
            "mode": mode,
            "summary": _build_summary(findings),
        },
        "findings": _group_findings(findings),
    }
    # Use print() directly so the output is clean JSON without Rich markup.
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Markdown format
# ---------------------------------------------------------------------------

def format_markdown(
    findings: Sequence[dict],
    console: Console,
    scan_path: str,
    mode: str = "normal",
) -> None:
    """Print a structured Markdown report to stdout."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    parts = [f"{sev_counts[s]} {s}" for s in _SEVERITY_ORDER if s in sev_counts]
    findings_summary = f"{len(findings)} ({', '.join(parts)})" if parts else "0"

    lines: list[str] = [
        "# LLM Armor Scan Report",
        "",
        f"**Scanned**: {scan_path}",
        f"**Date**: {today}",
        f"**Mode**: {mode}",
        f"**Findings**: {findings_summary}",
        "",
    ]

    for group in _group_findings(findings):
        rule_id = group["rule_id"]
        rule_name = group["rule_name"]
        severity = group["severity"]

        lines.append(f"## {rule_id}: {rule_name} ({severity})")
        lines.append("")

        description = group.get("description", "")
        if description:
            lines.append(description)
            lines.append("")

        lines.append("| File | Line |")
        lines.append("|------|------|")
        for loc in sorted(group["locations"], key=lambda x: (x["filepath"], x["line"])):
            lines.append(f"| {loc['filepath']} | {loc['line']} |")

        fix = group.get("fix_suggestion", "")
        if fix:
            lines.append("")
            lines.append(f"**Fix**: {fix}")

        lines.append("")
        lines.append("---")
        lines.append("")

    print("\n".join(lines))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_FORMATS = {
    "grouped": format_grouped,
    "flat": format_flat,
    "json": format_json,
    "md": format_markdown,
    "markdown": format_markdown,
}

VALID_FORMATS = list(_FORMATS.keys())

# Severities hidden in non-verbose mode.
_HIDDEN_IN_NORMAL = frozenset({"INFO", "LOW"})


def render(
    findings: Sequence[dict],
    fmt: str,
    console: Console,
    scan_path: str,
    verbose: bool = False,
    mode: str = "normal",
) -> None:
    """Render *findings* using the specified *fmt* format.

    :param findings: list of finding dicts from :func:`~llmarmor.scanner.run_scan`
    :param fmt: one of ``grouped``, ``flat``, ``json``, ``md``, ``markdown``
    :param console: Rich Console instance (used for terminal formats)
    :param scan_path: the path that was scanned (shown in headers)
    :param verbose: when ``True``, include INFO and LOW findings in output.
                    When ``False`` (default), INFO and LOW are hidden.
    :param mode: scan mode string for JSON/Markdown metadata
                 (``"normal"``, ``"strict"``, ``"verbose"``, ``"strict+verbose"``)
    :raises ValueError: if *fmt* is not recognised
    """
    formatter = _FORMATS.get(fmt)
    if formatter is None:
        raise ValueError(f"Unknown format {fmt!r}. Valid options: {', '.join(VALID_FORMATS)}")

    # Filter out INFO and LOW in non-verbose mode.
    if not verbose:
        findings = [f for f in findings if f["severity"] not in _HIDDEN_IN_NORMAL]

    # JSON and Markdown formatters accept an extra ``mode`` kwarg.
    if fmt in ("json", "md", "markdown"):
        formatter(findings, console, scan_path, mode=mode)  # type: ignore[call-arg]
    else:
        formatter(findings, console, scan_path)
