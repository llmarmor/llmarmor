"""CLI entry point for LLM Armor."""

import click
from rich.console import Console
from rich.panel import Panel

from llmarmor import __version__
from llmarmor.formatters import VALID_FORMATS, render
from llmarmor.scanner import run_scan

console = Console()

_RULE_GROUPS = [
    (
        "Active",
        "🟢",
        [
            ("LLM01", "Prompt Injection"),
            ("LLM02", "Sensitive Information Disclosure"),
            ("LLM07", "System Prompt Leakage"),
            ("LLM10", "Unbounded Consumption"),
        ],
    ),
    (
        "Planned",
        "🟡",
        [
            ("LLM05", "Improper Output Handling"),
            ("LLM08", "Excessive Agency"),
        ],
    ),
    (
        "Out of Scope",
        "🔴",
        [
            ("LLM03", "Supply Chain Vulnerabilities"),
            ("LLM04", "Data and Model Poisoning"),
            ("LLM06", "Insecure Plugin Design"),
            ("LLM09", "Misinformation"),
        ],
    ),
]


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
    "--format",
    "-f",
    "fmt",
    default="grouped",
    show_default=True,
    type=click.Choice(VALID_FORMATS, case_sensitive=False),
    help="Output format: grouped (default), flat, json, md/markdown.",
)
def scan(path: str, strict: bool, fmt: str) -> None:
    """Scan PATH for LLM security vulnerabilities."""
    # For non-JSON/markdown formats, show the header panel.
    if fmt not in ("json", "md", "markdown"):
        mode_label = " [bold yellow](strict mode)[/bold yellow]" if strict else ""
        console.print(
            Panel(
                f"[bold green]LLM Armor v{__version__}[/bold green]{mode_label}\n"
                f"Scanning: [cyan]{path}[/cyan]",
                title="🛡️ LLM Armor",
                border_style="blue",
            )
        )

    findings = run_scan(path, strict=strict)

    render(findings, fmt=fmt, console=console, scan_path=path)


@main.command()
def rules() -> None:
    """List all OWASP LLM Top 10 rules grouped by support status."""
    from rich.table import Table

    for group_name, icon, rule_entries in _RULE_GROUPS:
        table = Table(
            title=f"{icon} {group_name}",
            show_lines=True,
        )
        table.add_column("ID", style="bold cyan", width=8)
        table.add_column("Rule Name")

        for rule_id, name in rule_entries:
            table.add_row(rule_id, name)

        console.print(table)


if __name__ == "__main__":
    main()

