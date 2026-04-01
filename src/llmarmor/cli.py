"""CLI entry point for LLM Armor."""

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
    help="Output format: grouped (default), flat, json, md/markdown.",
)
def scan(path: str, strict: bool, verbose: bool, fmt: str) -> None:
    """Scan PATH for LLM security vulnerabilities."""
    mode = _build_mode(strict, verbose)

    # For non-JSON/markdown formats, show the header panel.
    if fmt not in ("json", "md", "markdown"):
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

    findings = run_scan(path, strict=strict)

    render(findings, fmt=fmt, console=console, scan_path=path, verbose=verbose, mode=mode)


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

