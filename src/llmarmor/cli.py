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
    """List all OWASP LLM Top 10 rules grouped by support status."""
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
