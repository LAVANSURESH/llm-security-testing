"""
AI-Based Cybersecurity SOC — Entry Point

AI agents autonomously perform SOC analyst duties:
  - Alert triage and severity classification
  - Threat intelligence and MITRE ATT&CK mapping
  - Log analysis and anomaly detection
  - Incident response playbook generation
  - SOC reporting and executive summaries
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc.models.alert import Alert
from soc.orchestrator.soc_orchestrator import SOCOrchestrator
from soc.dashboard.cli_dashboard import (
    print_banner, print_alert_received, print_incident_created,
    print_final_report, print_soc_metrics, print_false_positive,
    create_status_callback,
)

DEFAULT_ALERTS = os.path.join(os.path.dirname(__file__), "data", "sample_alerts.json")
DEFAULT_LOGS = os.path.join(os.path.dirname(__file__), "data", "sample_logs.json")


def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-Powered Security Operations Center",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process sample alerts autonomously
  python soc/main.py --mode auto

  # Process specific alert file
  python soc/main.py --mode auto --alerts path/to/alerts.json

  # Interactive mode (P1 incidents require confirmation)
  python soc/main.py --mode interactive

  # Process a single inline alert
  python soc/main.py --alert '{"source":"firewall","alert_type":"brute_force","severity":"high","description":"550 failed logins","raw_data":{}}'

  # Process only first N alerts
  python soc/main.py --mode auto --limit 3

  # Save reports to output directory
  python soc/main.py --mode auto --output ./reports
        """,
    )
    parser.add_argument("--mode", choices=["auto", "interactive"], default="auto",
                        help="auto=fully autonomous, interactive=confirm P1 incidents (default: auto)")
    parser.add_argument("--alerts", default=DEFAULT_ALERTS,
                        help="Path to JSON alert file (default: soc/data/sample_alerts.json)")
    parser.add_argument("--logs", default=DEFAULT_LOGS,
                        help="Path to JSON log file (default: soc/data/sample_logs.json)")
    parser.add_argument("--alert", type=str, default=None,
                        help="Single alert as JSON string")
    parser.add_argument("--model", default="claude-sonnet-4-6",
                        help="Claude model to use (default: claude-sonnet-4-6)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Process only the first N alerts")
    parser.add_argument("--output", type=str, default=None,
                        help="Directory to save incident reports as JSON files")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress agent status messages")
    return parser.parse_args()


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


def main():
    args = parse_args()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        print("Set it with: export ANTHROPIC_API_KEY=your-key-here")
        sys.exit(1)

    print_banner()

    orchestrator = SOCOrchestrator(
        model=args.model,
        api_key=api_key,
        interactive=(args.mode == "interactive"),
    )

    status_callback = create_status_callback(dashboard_enabled=not args.quiet)
    incidents = []

    # ── Single inline alert mode ─────────────────────────────────────────────
    if args.alert:
        try:
            alert_data = json.loads(args.alert)
            alert = Alert.from_dict(alert_data)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error parsing alert JSON: {e}")
            sys.exit(1)

        log_entries = []
        if os.path.exists(args.logs):
            with open(args.logs) as f:
                log_entries = json.load(f)

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

        with open(args.alerts) as f:
            alerts_data = json.load(f)

        log_entries = []
        if os.path.exists(args.logs):
            with open(args.logs) as f:
                log_entries = json.load(f)

        if args.limit:
            alerts_data = alerts_data[:args.limit]

        print(f"\nProcessing {len(alerts_data)} alert(s) from {args.alerts}\n")

        for alert_data in alerts_data:
            alert = Alert.from_dict(alert_data)
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
