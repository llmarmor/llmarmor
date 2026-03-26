"""CLI entry point for LLM Armor."""

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from llmarmor import __version__
from llmarmor.scanner import run_scan

console = Console()

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
}

_RULE_LIST = [
    ("LLM01", "Prompt Injection", "🟢 Active"),
    ("LLM02", "Sensitive Information Disclosure", "🟢 Active"),
    ("LLM05", "Improper Output Handling", "🟡 Coming soon"),
    ("LLM07", "System Prompt Leakage", "🟢 Active"),
    ("LLM08", "Excessive Agency", "🟡 Coming soon"),
    ("LLM10", "Unbounded Consumption", "🟢 Active"),
]


@click.group()
@click.version_option(version=__version__, prog_name="llmarmor")
def main() -> None:
    """🛡️ LLM Armor — Scan your AI code for OWASP LLM Top 10 vulnerabilities."""


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def scan(path: str) -> None:
    """Scan PATH for LLM security vulnerabilities."""
    console.print(
        Panel(
            f"[bold green]LLM Armor v{__version__}[/bold green]\n"
            f"Scanning: [cyan]{path}[/cyan]",
            title="🛡️ LLM Armor",
            border_style="blue",
        )
    )

    findings = run_scan(path)

    if not findings:
        console.print("[green]✅ No vulnerabilities detected.[/green]")
        return

    # Group by severity
    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
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
                f["filepath"],
                str(f["line"]),
                f["description"],
            )

        console.print(table)

    # Summary panel
    totals = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in _SEVERITY_COLORS}
    summary_lines = [f"[bold]Total findings: {len(findings)}[/bold]"]
    for sev, count in totals.items():
        if count:
            color = _SEVERITY_COLORS[sev]
            summary_lines.append(f"  [{color}]{sev}[/{color}]: {count}")

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="📊 Scan Summary",
            border_style="yellow",
        )
    )


@main.command()
def rules() -> None:
    """List all supported OWASP LLM Top 10 detection rules."""
    table = Table(title="OWASP LLM Top 10 Rules", show_lines=True)
    table.add_column("ID", style="bold cyan", width=8)
    table.add_column("Rule Name")
    table.add_column("Status", width=16)

    for rule_id, name, status in _RULE_LIST:
        table.add_row(rule_id, name, status)

    console.print(table)


if __name__ == "__main__":
    main()
