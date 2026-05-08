"""
AI-Based Cybersecurity SOC — Entry Point

AI agents autonomously perform SOC analyst duties:
  - Alert triage and severity classification
  - Threat intelligence and MITRE ATT&CK mapping
  - Log analysis and anomaly detection
  - Incident response playbook generation
  - SOC reporting and executive summaries

Provider selection (first match wins):
  --provider gemini    / GEMINI_API_KEY
  --provider anthropic / ANTHROPIC_API_KEY
  --provider openai    / OPENAI_API_KEY

Usage examples:
  # Autonomous mode with auto-detected provider
  python soc/main.py

  # Specify provider explicitly
  python soc/main.py --provider gemini

  # Process specific alert file
  python soc/main.py --alerts path/to/alerts.json

  # Interactive mode (P1 incidents require confirmation)
  python soc/main.py --mode interactive

  # Single inline alert
  python soc/main.py --alert '{...json...}'

  # Save reports
  python soc/main.py --output ./reports --limit 3
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc.agents.base_agent import detect_provider, PROVIDER_DEFAULTS
from soc.models.alert import Alert
from soc.orchestrator.soc_orchestrator import SOCOrchestrator
from soc.dashboard.cli_dashboard import (
    print_banner,
    print_alert_received,
    print_incident_created,
    print_final_report,
    print_soc_metrics,
    print_false_positive,
    create_status_callback,
)

DEFAULT_ALERTS = os.path.join(os.path.dirname(__file__), "data", "sample_alerts.json")
DEFAULT_LOGS = os.path.join(os.path.dirname(__file__), "data", "sample_logs.json")


def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-Powered Security Operations Center",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Provider selection (first available env var wins unless --provider is given):
  GEMINI_API_KEY    → gemini-2.0-flash
  ANTHROPIC_API_KEY → claude-sonnet-4-6
  OPENAI_API_KEY    → gpt-4o

Examples:
  python soc/main.py
  python soc/main.py --provider gemini
  python soc/main.py --provider anthropic --model claude-opus-4-7
  python soc/main.py --provider openai --model gpt-4o --limit 3
  python soc/main.py --mode interactive --alerts path/to/alerts.json
  python soc/main.py --output ./reports
        """,
    )
    parser.add_argument(
        "--provider",
        choices=["gemini", "anthropic", "openai"],
        default=None,
        help="LLM provider to use (auto-detected from env vars if not set)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override (default: gemini-2.0-flash / claude-sonnet-4-6 / gpt-4o)",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "interactive"],
        default="auto",
        help="auto=fully autonomous, interactive=confirm P1 incidents (default: auto)",
    )
    parser.add_argument(
        "--alerts",
        default=DEFAULT_ALERTS,
        help="Path to JSON alert file (default: soc/data/sample_alerts.json)",
    )
    parser.add_argument(
        "--logs",
        default=DEFAULT_LOGS,
        help="Path to JSON log file (default: soc/data/sample_logs.json)",
    )
    parser.add_argument(
        "--alert",
        type=str,
        default=None,
        help="Single alert as a JSON string",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N alerts",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Directory to save incident reports as JSON files",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-agent status messages",
    )
    parser.add_argument(
        "--siem-format",
        choices=["auto", "splunk", "elastic", "sentinel"],
        default="auto",
        help="SIEM format for input alert file (default: auto-detect)",
    )
    return parser.parse_args()


def _resolve_provider_and_key(args) -> tuple:
    """Return (provider, api_key, model) from CLI args + env vars."""
    try:
        provider, api_key = detect_provider(preferred=args.provider)
    except ValueError as e:
        print(f"\nError: {e}")
        print("\nSet one of the following environment variables:")
        print("  export GEMINI_API_KEY=your-gemini-key")
        print("  export ANTHROPIC_API_KEY=your-anthropic-key")
        print("  export OPENAI_API_KEY=your-openai-key")
        sys.exit(1)
    model = args.model or PROVIDER_DEFAULTS[provider]
    return provider, api_key, model


def save_reports(incidents, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    for incident in incidents:
        report_path = os.path.join(output_dir, f"{incident.id}.json")
        with open(report_path, "w") as f:
            data = incident.to_dict()
            data["final_report"] = incident.final_report
            data["executive_summary"] = incident.executive_summary
            data["playbook"] = incident.playbook
            json.dump(data, f, indent=2)
    print(f"\nReports saved to: {output_dir}/")


def _load_alerts_with_format(alert_file: str, siem_format: str) -> list:
    """Load alerts from file, optionally parsing SIEM-specific formats."""
    if siem_format != "auto":
        from soc.tools.siem_integration import load_alerts_from_file
        alerts = load_alerts_from_file(alert_file, format=siem_format)
        return [a.to_dict() for a in alerts]

    with open(alert_file) as f:
        return json.load(f)


def main():
    args = parse_args()
    provider, api_key, model = _resolve_provider_and_key(args)

    print_banner(provider=provider, model=model)

    orchestrator = SOCOrchestrator(
        model=model,
        api_key=api_key,
        provider=provider,
        interactive=(args.mode == "interactive"),
    )

    status_callback = create_status_callback(dashboard_enabled=not args.quiet)
    incidents = []

    log_entries = []
    if os.path.exists(args.logs):
        with open(args.logs) as f:
            log_entries = json.load(f)

    # ── Single inline alert mode ─────────────────────────────────────────────
    if args.alert:
        try:
            alert_data = json.loads(args.alert)
            alert = Alert.from_dict(alert_data)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error parsing alert JSON: {e}")
            sys.exit(1)

        print_alert_received(alert)
        incident = orchestrator.process_alert(alert, log_entries, status_callback)
        if incident:
            print_incident_created(incident)
            print_final_report(incident)
            incidents.append(incident)
        else:
            print_false_positive(alert.id)

    # ── Batch file mode ──────────────────────────────────────────────────────
    else:
        if not os.path.exists(args.alerts):
            print(f"Alert file not found: {args.alerts}")
            sys.exit(1)

        try:
            alerts_data = _load_alerts_with_format(args.alerts, args.siem_format)
        except Exception as e:
            print(f"Error loading alerts: {e}")
            sys.exit(1)

        if args.limit:
            alerts_data = alerts_data[: args.limit]

        print(f"\nProcessing {len(alerts_data)} alert(s) from {args.alerts}\n")

        for alert_data in alerts_data:
            alert = Alert.from_dict(alert_data) if isinstance(alert_data, dict) else alert_data
            print_alert_received(alert)

            incident = orchestrator.process_alert(alert, log_entries, status_callback)
            if incident:
                print_incident_created(incident)
                print_final_report(incident)
                incidents.append(incident)
            else:
                print_false_positive(alert.id)

    # ── Session summary ──────────────────────────────────────────────────────
    if incidents:
        metrics = orchestrator.get_soc_metrics()
        print_soc_metrics(metrics)

        if args.output:
            save_reports(incidents, args.output)

    print(f"\nSOC session complete. Incidents created: {len(incidents)}\n")


if __name__ == "__main__":
    main()
