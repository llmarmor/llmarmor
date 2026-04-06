"""Output formatters for LLM Armor scan results.

Supported formats:
- ``grouped`` (default): findings grouped by rule, one section per rule
- ``flat``: one finding per block with structured What/Why/Fix/Ref template
- ``json``: grouped JSON with ``meta`` and ``findings`` blocks
- ``md`` / ``markdown``: Markdown report with structured sections
- ``sarif``: SARIF 2.1.0 format for GitHub Code Scanning and security dashboards
"""

import json
import os
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from typing import IO, Sequence

from rich.console import Console

from llmarmor import __version__
from llmarmor.messages import RULE_URLS

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

def _get_rule_name(rule_id: str, fallback: str = "") -> str:
    """Return the canonical rule name for *rule_id* from the registry.

    Falls back to *fallback* (or the rule_id itself) if the registry does not
    know the rule.  Using the registry avoids duplicating the _RULE_NAMES dict.
    """
    try:
        from llmarmor.registry import registry as _registry
        return _registry.get(rule_id).name
    except (KeyError, Exception):
        return fallback or rule_id


def format_grouped(findings: Sequence[dict], console: Console, scan_path: str) -> None:
    """Print findings grouped by rule to *console* (default format).

    Each (rule_id, severity) pair becomes its own section so that every section
    header reflects exactly the severity of the findings listed inside it.
    This matches the behaviour of tools like Bandit and Checkov where the same
    rule at different severities produces separate groups.
    """
    if not findings:
        console.print("[green]✅ No vulnerabilities detected.[/green]")
        return

    # Group findings by (rule_id, severity) — one group per unique combination.
    by_rule: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        by_rule[(f["rule_id"], f["severity"])].append(f)

    # Sort groups: most critical severity first, then alphabetically by rule_id.
    sorted_keys = sorted(
        by_rule.keys(),
        key=lambda k: (_severity_sort_key(k[1]), k[0]),
    )

    for rule_id, severity in sorted_keys:
        group = by_rule[(rule_id, severity)]
        color = _SEVERITY_COLORS.get(severity, "white")
        rule_name = group[0].get("rule_name") or _get_rule_name(rule_id)

        console.print(
            f"\n[bold]━━━ {rule_id}: {rule_name} ([{color}]{severity}[/{color}]) ━━━[/bold]"
        )

        # All findings in this group share the same description (same rule + severity).
        description = group[0].get("description", "")
        if description:
            console.print(f"{description}\n")

        # Locations — every entry here has the same severity, no annotation needed.
        for f in sorted(group, key=lambda x: (x["filepath"], x["line"])):
            fp = truncate_path(f["filepath"])
            console.print(f"  [cyan]→[/cyan] {fp}:{f['line']}")

        # Fix suggestion (all findings in the group share the same fix).
        fix = next((f.get("fix_suggestion") for f in group if f.get("fix_suggestion")), None)
        if fix:
            console.print(f"\n[dim]Fix: {fix}[/dim]")

        # Reference URL — show after the fix line.
        ref_url = next((f.get("reference_url") for f in group if f.get("reference_url")), None)
        if ref_url:
            console.print(f"[dim]Ref: {ref_url}[/dim]")

    # Summary line
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    parts = [f"{sev_counts[s]} {s}" for s in _SEVERITY_ORDER if s in sev_counts]
    console.print(f"\n[bold]Summary: {len(findings)} finding(s) ({', '.join(parts)})[/bold]")


# ---------------------------------------------------------------------------
# Flat format (legacy, one line per finding)
# ---------------------------------------------------------------------------

def _first_sentence(text: str) -> str:
    """Return the first sentence of *text* (up to the first period, or full text if short)."""
    if not text:
        return text
    idx = text.find(". ")
    if idx > 0 and idx < 120:
        return text[: idx + 1]
    return text[:120].rstrip() + ("..." if len(text) > 120 else "")


def format_flat(findings: Sequence[dict], console: Console, scan_path: str) -> None:
    """Print one structured block per finding, ordered by severity.

    Each block follows the What/Why/Fix/Ref template:

    .. code-block:: text

        [LLM01] [HIGH] — <one-line summary>
          Location: path/to/file.py:42

        What: <description>
        Why:  <attack scenario>
        Fix:  <remediation>
        Ref:  <OWASP URL>
    """
    if not findings:
        console.print("[green]✅ No vulnerabilities detected.[/green]")
        return

    # Sort by severity (most critical first), then filepath/line.
    sorted_findings = sorted(
        findings,
        key=lambda f: (_severity_sort_key(f["severity"]), f.get("filepath", ""), f.get("line", 0)),
    )

    for f in sorted_findings:
        rule_id = f["rule_id"]
        severity = f["severity"]
        color = _SEVERITY_COLORS.get(severity, "white")
        summary = _first_sentence(f.get("description", ""))
        fp = truncate_path(f.get("filepath", ""))
        line = f.get("line", 0)
        what = f.get("description", "")
        why = f.get("why", "")
        fix = f.get("fix_suggestion", "")
        ref = f.get("reference_url", RULE_URLS.get(rule_id, ""))

        console.print(
            f"\n[bold][{rule_id}] [[{color}]{severity}[/{color}]] — {summary}[/bold]"
        )
        console.print(f"  [cyan]Location:[/cyan] {fp}:{line}")
        if what:
            console.print(f"\n[bold]What:[/bold] {what}")
        if why:
            console.print(f"[bold]Why: [/bold] {why}")
        if fix:
            console.print(f"[bold]Fix: [/bold] {fix}")
        if ref:
            console.print(f"[bold]Ref: [/bold] [link={ref}]{ref}[/link]")

    # Summary line
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
    """Group flat findings by (rule_id, severity) → locations list.

    Grouping excludes the description so that findings whose severity was
    promoted by strict mode (which may have a different description text) are
    still merged into the same group rather than split into two.
    """
    groups: dict[tuple, dict] = {}
    for f in findings:
        key = (f["rule_id"], f["severity"])
        if key not in groups:
            rule_id = f["rule_id"]
            groups[key] = {
                "rule_id": rule_id,
                "rule_name": f.get("rule_name") or _get_rule_name(rule_id),
                "severity": f["severity"],
                "description": f.get("description", ""),
                "fix_suggestion": f.get("fix_suggestion", ""),
                "why": f.get("why", ""),
                "reference_url": f.get("reference_url", RULE_URLS.get(rule_id, "")),
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
            lines.append(f"**What**: {description}")
            lines.append("")

        why = group.get("why", "")
        if why:
            lines.append(f"**Why**: {why}")
            lines.append("")

        lines.append("| File | Line |")
        lines.append("|------|------|")
        for loc in sorted(group["locations"], key=lambda x: (x["filepath"], x["line"])):
            lines.append(f"| {loc['filepath']} | {loc['line']} |")

        fix = group.get("fix_suggestion", "")
        if fix:
            lines.append("")
            lines.append(f"**Fix**: {fix}")

        ref = group.get("reference_url", "")
        if ref:
            lines.append("")
            lines.append(f"**Ref**: [{ref}]({ref})")

        lines.append("")
        lines.append("---")
        lines.append("")

    print("\n".join(lines))


# ---------------------------------------------------------------------------
# SARIF 2.1.0 format
# ---------------------------------------------------------------------------

# SARIF severity level mapping (SARIF 2.1.0 §3.27.10)
_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_OWASP_HELP_URI = (
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)


def format_sarif(
    findings: Sequence[dict],
    console: Console,
    scan_path: str,
    mode: str = "normal",
) -> None:
    """Print findings in SARIF 2.1.0 format to stdout.

    The output is suitable for GitHub Code Scanning, VS Code SARIF Viewer,
    and any tool that consumes the SARIF standard.

    Severity mapping:
    - CRITICAL / HIGH → error
    - MEDIUM → warning
    - LOW / INFO → note

    SARIF compliance notes:
    - ``message.text`` is concise and descriptive (not the structured What/Why/Fix/Ref
      template — that is for human-readable formats only).
    - ``fixes[]`` carries remediation guidance.
    - ``helpUri`` on each rule points to the OWASP rule-specific page.
    - ``reference_url`` is included in result ``properties`` when available.
    """
    # Build the rules array from unique rule IDs encountered in findings.
    rules_seen: dict[str, dict] = {}
    for f in findings:
        rule_id = f["rule_id"]
        if rule_id not in rules_seen:
            short_desc = f.get("description", "")
            # Truncate to a reasonable length for the short description.
            if len(short_desc) > 120:
                short_desc = short_desc[:117] + "..."
            # Use rule-specific OWASP URL if available, fall back to top-level page.
            help_uri = RULE_URLS.get(rule_id, _OWASP_HELP_URI)
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.get("rule_name", rule_id),
                "shortDescription": {"text": short_desc or rule_id},
                "fullDescription": {"text": f.get("description", "")},
                "helpUri": help_uri,
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                },
                "properties": {
                    "tags": ["security", "llm", f["rule_id"].lower()],
                },
            }

    results = []
    for f in findings:
        fix = f.get("fix_suggestion", "")
        result: dict = {
            "ruleId": f["rule_id"],
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f.get("description", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("filepath", ""),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, f.get("line", 1)),
                        },
                    },
                }
            ],
        }
        if fix:
            result["fixes"] = [{"description": {"text": fix}}]
        # Include reference_url and why in properties when available.
        extra_props: dict = {}
        ref_url = f.get("reference_url", "")
        if ref_url:
            extra_props["reference_url"] = ref_url
        why = f.get("why", "")
        if why:
            extra_props["why"] = why
        if extra_props:
            result["properties"] = extra_props
        results.append(result)

    sarif_output = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LLM Armor",
                        "version": __version__,
                        "informationUri": "https://llmarmor.dev",
                        "rules": list(rules_seen.values()),
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": f"file:///{scan_path}/"},
                },
                "results": results,
            }
        ],
    }

    print(json.dumps(sarif_output, indent=2))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_FORMATS = {
    "grouped": format_grouped,
    "flat": format_flat,
    "json": format_json,
    "md": format_markdown,
    "markdown": format_markdown,
    "sarif": format_sarif,
}

VALID_FORMATS = list(_FORMATS.keys())

# Severities hidden in non-verbose mode.
_HIDDEN_IN_NORMAL = frozenset({"INFO", "LOW"})

# Formats that write to stdout via print() rather than the Rich console.
_STDOUT_FORMATS = frozenset({"json", "md", "markdown", "sarif"})


def render(
    findings: Sequence[dict],
    fmt: str,
    console: Console,
    scan_path: str,
    verbose: bool = False,
    mode: str = "normal",
    quiet: bool = False,
    output_file: str | None = None,
) -> None:
    """Render *findings* using the specified *fmt* format.

    :param findings: list of finding dicts from :func:`~llmarmor.scanner.run_scan`
    :param fmt: one of ``grouped``, ``flat``, ``json``, ``md``, ``markdown``, ``sarif``
    :param console: Rich Console instance (used for terminal formats)
    :param scan_path: the path that was scanned (shown in headers)
    :param verbose: when ``True``, include INFO and LOW findings in output.
                    When ``False`` (default), INFO and LOW are hidden.
    :param mode: scan mode string for JSON/Markdown metadata
                 (``"normal"``, ``"strict"``, ``"verbose"``, ``"strict+verbose"``)
    :param quiet: when ``True``, suppress ALL output. Only the exit code communicates results.
    :param output_file: when set, write formatter output to this file path instead of stdout.
                        For grouped/flat (Rich formats), plain text is written (no markup).
                        For json/md/sarif, the output is written directly.
    :raises ValueError: if *fmt* is not recognised
    """
    formatter = _FORMATS.get(fmt)
    if formatter is None:
        raise ValueError(f"Unknown format {fmt!r}. Valid options: {', '.join(VALID_FORMATS)}")

    if quiet:
        return  # Suppress all output; exit code communicates the result.

    # Filter out INFO and LOW in non-verbose mode.
    if not verbose:
        findings = [f for f in findings if f["severity"] not in _HIDDEN_IN_NORMAL]

    if output_file:
        _render_to_file(findings, fmt, formatter, scan_path, mode, output_file)
        return

    # JSON, Markdown, and SARIF formatters accept an extra ``mode`` kwarg.
    if fmt in _STDOUT_FORMATS:
        formatter(findings, console, scan_path, mode=mode)  # type: ignore[call-arg]
    else:
        formatter(findings, console, scan_path)


def _render_to_file(
    findings: Sequence[dict],
    fmt: str,
    formatter: object,
    scan_path: str,
    mode: str,
    output_file: str,
) -> None:
    """Write formatted output to *output_file*.

    For grouped/flat (Rich formats), plain text is written (ANSI/markup stripped).
    For json/md/sarif, the output is written directly.
    """
    import io

    if fmt in _STDOUT_FORMATS:
        # Capture stdout-based output (print calls) and write to file.
        old_stdout = __import__("sys").stdout
        buf = io.StringIO()
        __import__("sys").stdout = buf
        try:
            formatter(findings, None, scan_path, mode=mode)  # type: ignore[call-arg]
        finally:
            __import__("sys").stdout = old_stdout
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
    else:
        # Rich-based formats: render to a plain-text console, then write to file.
        from io import StringIO
        from rich.console import Console as _Console

        buf = StringIO()
        file_console = _Console(file=buf, highlight=False, markup=False, width=120)
        formatter(findings, file_console, scan_path)  # type: ignore[call-arg]
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(buf.getvalue())
