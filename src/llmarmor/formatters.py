"""Output formatters for LLM Armor scan results.

Supported formats:
- ``grouped`` (default): findings grouped by rule, one section per rule
- ``flat``: one line per finding (legacy format)
- ``json``: JSON array of all findings
- ``md`` / ``markdown``: Markdown report
"""

import json
import os
import shutil
from collections import defaultdict
from datetime import date
from typing import Sequence

from rich.console import Console
from rich.table import Table

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

def format_json(findings: Sequence[dict], console: Console, scan_path: str) -> None:
    """Print findings as a pretty-printed JSON array to stdout."""
    # Use print() directly so the output is clean JSON without Rich markup.
    print(json.dumps(list(findings), indent=2))


# ---------------------------------------------------------------------------
# Markdown format
# ---------------------------------------------------------------------------

def format_markdown(findings: Sequence[dict], console: Console, scan_path: str) -> None:
    """Print a structured Markdown report to stdout."""
    today = date.today().isoformat()

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
        f"**Findings**: {findings_summary}",
        "",
    ]

    # Group by rule
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_rule[f["rule_id"]].append(f)

    def _group_severity(rule_id: str) -> int:
        group = by_rule[rule_id]
        return min(_severity_sort_key(f["severity"]) for f in group)

    sorted_rules = sorted(by_rule.keys(), key=_group_severity)

    for rule_id in sorted_rules:
        group = by_rule[rule_id]
        worst_sev = min(group, key=lambda f: _severity_sort_key(f["severity"]))["severity"]
        rule_name = group[0].get("rule_name") or _RULE_NAMES.get(rule_id, rule_id)

        lines.append(f"## {rule_id}: {rule_name} ({worst_sev})")
        lines.append("")

        description = group[0].get("description", "")
        if description:
            lines.append(description)
            lines.append("")

        lines.append("| File | Line |")
        lines.append("|------|------|")
        for f in sorted(group, key=lambda x: (x["filepath"], x["line"])):
            lines.append(f"| {f['filepath']} | {f['line']} |")

        fix = next((f.get("fix_suggestion") for f in group if f.get("fix_suggestion")), None)
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


def render(
    findings: Sequence[dict],
    fmt: str,
    console: Console,
    scan_path: str,
) -> None:
    """Render *findings* using the specified *fmt* format.

    :param findings: list of finding dicts
    :param fmt: one of ``grouped``, ``flat``, ``json``, ``md``, ``markdown``
    :param console: Rich Console instance (used for terminal formats)
    :param scan_path: the path that was scanned (shown in headers)
    :raises ValueError: if *fmt* is not recognised
    """
    formatter = _FORMATS.get(fmt)
    if formatter is None:
        raise ValueError(f"Unknown format {fmt!r}. Valid options: {', '.join(VALID_FORMATS)}")
    formatter(findings, console, scan_path)
