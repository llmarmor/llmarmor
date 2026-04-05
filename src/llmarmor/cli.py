"""CLI entry point for LLM Armor."""

import sys

import click
from rich.console import Console
from rich.panel import Panel

from llmarmor import __version__
from llmarmor.formatters import VALID_FORMATS, render
from llmarmor.registry import Status, registry
from llmarmor.scanner import run_scan

console = Console()


def _build_mode(strict: bool, verbose: bool) -> str:
    """Return the mode string for JSON/Markdown metadata."""
    if strict and verbose:
        return "strict+verbose"
    if strict:
        return "strict"
    if verbose:
        return "verbose"
    return "normal"


def _compute_exit_code(findings: list[dict]) -> int:
    """Return an exit code based on the worst finding severity.

    Exit codes follow the convention used by semgrep and bandit:

    - ``0`` — no findings at or above MEDIUM (clean or INFO/LOW only)
    - ``1`` — at least one HIGH or MEDIUM finding
    - ``2`` — at least one CRITICAL finding (must fix immediately)
    """
    severities = {f["severity"] for f in findings}
    if "CRITICAL" in severities:
        return 2
    if severities & {"HIGH", "MEDIUM"}:
        return 1
    return 0


@click.group()
@click.version_option(version=__version__, prog_name="llmarmor")
def main() -> None:
    """🛡️ LLM Armor — Scan your AI code for OWASP LLM Top 10 vulnerabilities."""


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help=(
        "Enable strict scanning. Flags borderline patterns including plain tainted "
        "variables in role messages and promotes INFO findings to WARNING/MEDIUM."
    ),
)
@click.option(
    "--verbose",
    "-v",
    "verbose",
    is_flag=True,
    default=False,
    help=(
        "Show all findings including INFO and LOW severity. "
        "By default, only CRITICAL, HIGH, and MEDIUM findings are shown."
    ),
)
@click.option(
    "--format",
    "-f",
    "fmt",
    default="grouped",
    show_default=True,
    type=click.Choice(VALID_FORMATS, case_sensitive=False),
    help="Output format: grouped (default), flat, json, md/markdown, sarif.",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=True),
    help=(
        "Path to a .llmarmor.yaml configuration file. "
        "Auto-detected in the scan root if not specified."
    ),
)
def scan(path: str, strict: bool, verbose: bool, fmt: str, config_path: str | None) -> None:
    """Scan PATH for LLM security vulnerabilities."""
    from llmarmor.config import load_config

    # Load configuration file (auto-detected or explicit).
    cfg = load_config(config_path=config_path, scan_root=path)
    if cfg is not None:
        # CLI flags override config file values.
        if not strict:
            strict = cfg.strict

    mode = _build_mode(strict, verbose)

    # For non-JSON/markdown/SARIF formats, show the header panel.
    if fmt not in ("json", "md", "markdown", "sarif"):
        mode_parts = []
        if strict:
            mode_parts.append("[bold yellow](strict)[/bold yellow]")
        if verbose:
            mode_parts.append("[bold cyan](verbose)[/bold cyan]")
        mode_label = " " + " ".join(mode_parts) if mode_parts else ""
        console.print(
            Panel(
                f"[bold green]LLM Armor v{__version__}[/bold green]{mode_label}\n"
                f"Scanning: [cyan]{path}[/cyan]",
                title="🛡️ LLM Armor",
                border_style="blue",
            )
        )

    findings = run_scan(path, strict=strict, config=cfg)

    render(findings, fmt=fmt, console=console, scan_path=path, verbose=verbose, mode=mode)

    sys.exit(_compute_exit_code(findings))


@main.command()
def rules() -> None:
    """List all OWASP LLM Top 10 rules grouped by support status."""
    from rich.table import Table

    _STATUS_GROUPS = [
        (Status.ACTIVE, "Active", "🟢"),
        (Status.PLANNED, "Planned", "🟡"),
        (Status.OUT_OF_SCOPE, "Out of Scope", "🔴"),
    ]

    for status, group_name, icon in _STATUS_GROUPS:
        rules_in_group = registry.by_status(status)
        if not rules_in_group:
            continue

        table = Table(
            title=f"{icon} {group_name}",
            show_lines=True,
        )
        table.add_column("ID", style="bold cyan", width=8)
        table.add_column("Rule Name")

        for rule in rules_in_group:
            table.add_row(rule.rule_id, rule.name)

        console.print(table)


if __name__ == "__main__":
    main()

