"""Rich CLI dashboard for the AI SOC application."""

from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich.markdown import Markdown
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from soc.models.incident import Incident

console = Console() if RICH_AVAILABLE else None

PRIORITY_COLORS = {"P1": "bold red", "P2": "red", "P3": "yellow", "P4": "green"}
SEVERITY_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}
STATUS_COLORS = {"open": "red", "investigating": "yellow", "contained": "blue", "resolved": "green"}

PROVIDER_LABELS = {
    "gemini": ("Google Gemini", "green"),
    "anthropic": ("Anthropic Claude", "cyan"),
    "openai": ("OpenAI GPT", "bright_green"),
}


def print_banner(provider: str = "anthropic", model: str = "claude-sonnet-4-6"):
    provider_name, provider_color = PROVIDER_LABELS.get(provider, (provider, "white"))

    if not RICH_AVAILABLE:
        print("=" * 64)
        print("  AI-POWERED SECURITY OPERATIONS CENTER")
        print(f"  Provider: {provider_name} | Model: {model}")
        print("  Autonomous SOC Agents")
        print("=" * 64)
        return

    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold cyan]AI-POWERED SECURITY OPERATIONS CENTER[/bold cyan]\n"
            f"[dim]Provider: [{provider_color}]{provider_name}[/{provider_color}]"
            f"  |  Model: [bold]{model}[/bold][/dim]\n"
            "[dim]Autonomous SOC Agents · Triage · Threat Intel · IR · Reporting[/dim]"
        ),
        border_style="cyan",
        padding=(1, 4),
    ))
    console.print()


def print_agent_status(agent_name: str, message: str, style: str = ""):
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    if not RICH_AVAILABLE:
        print(f"[{timestamp}] [{agent_name}] {message}")
        return

    agent_styles = {
        "TriageAgent": "bold yellow",
        "ThreatIntelAgent": "bold magenta",
        "LogAnalysisAgent": "bold blue",
        "IRAgent": "bold red",
        "ReportingAgent": "bold green",
        "Orchestrator": "bold cyan",
    }
    color = agent_styles.get(agent_name, "white")
    console.print(f"  [dim]{timestamp}[/dim] [[{color}]{agent_name}[/{color}]] {message}")


def print_alert_received(alert):
    if not RICH_AVAILABLE:
        print(f"\n[ALERT] {alert.alert_type} | Severity: {alert.severity} | Source: {alert.source}")
        return

    sev_color = SEVERITY_COLORS.get(alert.severity.lower(), "white")
    console.print()
    console.print(Rule(f"[bold]New Alert: {alert.id}[/bold]", style="yellow"))
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Field", style="dim", width=15)
    table.add_column("Value")
    table.add_row("Type", f"[bold]{alert.alert_type}[/bold]")
    table.add_row("Severity", f"[{sev_color}]{alert.severity.upper()}[/{sev_color}]")
    table.add_row("Source", alert.source)
    table.add_row("Description", alert.description[:80])
    if alert.source_ip:
        table.add_row("Source IP", alert.source_ip)
    if alert.user:
        table.add_row("User", alert.user)
    if alert.hostname:
        table.add_row("Hostname", alert.hostname)
    console.print(table)


def print_incident_created(incident: Incident):
    if not RICH_AVAILABLE:
        print(
            f"\n[INCIDENT] {incident.id} | Priority: {incident.priority}"
            f" | Risk: {incident.risk_score}/10"
        )
        return

    p_color = PRIORITY_COLORS.get(incident.priority, "white")
    risk_color = (
        "bold red" if incident.risk_score >= 7
        else "yellow" if incident.risk_score >= 4
        else "green"
    )
    ttp_str = ", ".join(incident.ttps[:6]) if incident.ttps else "None identified"
    if len(incident.ttps) > 6:
        ttp_str += f" +{len(incident.ttps) - 6} more"

    console.print()
    console.print(Panel(
        f"[bold]Incident ID:[/bold]     {incident.id}\n"
        f"[bold]Priority:[/bold]        [{p_color}]{incident.priority}[/{p_color}]\n"
        f"[bold]Classification:[/bold]  {incident.classification}\n"
        f"[bold]Risk Score:[/bold]      [{risk_color}]{incident.risk_score}/10[/{risk_color}]\n"
        f"[bold]MITRE TTPs:[/bold]      {ttp_str}\n"
        f"[bold]IOCs:[/bold]            {len(incident.iocs)} indicator(s)\n"
        f"[bold]Affected Assets:[/bold] {', '.join(incident.affected_assets) or 'Unknown'}",
        title="[bold green]Incident Created[/bold green]",
        border_style="green",
    ))


def print_final_report(incident: Incident):
    if not RICH_AVAILABLE:
        print("\n" + "=" * 64)
        print("INCIDENT REPORT")
        print("=" * 64)
        if incident.final_report:
            print(incident.final_report)
        return

    console.print()
    console.print(Rule("[bold cyan]INCIDENT REPORT[/bold cyan]", style="cyan"))
    if incident.final_report:
        console.print(Markdown(incident.final_report))
    console.print()


def print_soc_metrics(metrics: dict):
    if not RICH_AVAILABLE:
        print(f"\n[SOC METRICS] Total: {metrics.get('total_incidents', 0)}")
        return

    console.print()
    console.print(Rule("[bold]SOC Session Metrics[/bold]"))

    table = Table(title="Incident Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Total Incidents", str(metrics.get("total_incidents", 0)))
    table.add_row("Critical (P1)", f"[bold red]{metrics.get('critical_incidents', 0)}[/bold red]")
    table.add_row("Open / Investigating", f"[yellow]{metrics.get('open_incidents', 0)}[/yellow]")
    table.add_row("Avg Risk Score", f"{metrics.get('average_risk_score', 0)}/10")

    by_priority = metrics.get("by_priority", {})
    if by_priority:
        prio_str = "  ".join(
            f"[{PRIORITY_COLORS.get(p, 'white')}]{p}:{c}[/{PRIORITY_COLORS.get(p, 'white')}]"
            for p, c in by_priority.items() if c > 0
        )
        table.add_row("By Priority", prio_str or "—")

    console.print(table)
    console.print()


def print_false_positive(alert_id: str):
    if not RICH_AVAILABLE:
        print(f"[FALSE POSITIVE] Alert {alert_id} dismissed")
        return
    console.print(
        f"  [dim]→[/dim] Alert [bold]{alert_id}[/bold] "
        "[green]dismissed as false positive[/green]"
    )


def create_status_callback(dashboard_enabled: bool = True):
    """Return a (agent_name, message) → None callback for the orchestrator."""
    def callback(agent_name: str, message: str):
        if dashboard_enabled:
            print_agent_status(agent_name, message)
    return callback
