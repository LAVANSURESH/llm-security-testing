"""SOC Orchestrator — coordinates all agents through the incident response workflow."""

import json
import os
import sys
from typing import Callable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from soc.models.alert import Alert
from soc.models.incident import Incident
from soc.agents.triage_agent import TriageAgent
from soc.agents.threat_intel_agent import ThreatIntelAgent
from soc.agents.log_analysis_agent import LogAnalysisAgent
from soc.agents.incident_response_agent import IncidentResponseAgent
from soc.agents.reporting_agent import ReportingAgent
from soc.tools.analysis_tools import calculate_risk_score


class SOCOrchestrator:
    """
    Orchestrates the full SOC workflow:
    Alert → Triage → Threat Intel → Log Analysis → IR Planning → Reporting
    """

    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str = None, interactive: bool = False):
        self.model = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.interactive = interactive
        self.incidents: List[Incident] = []

        self.triage = TriageAgent(model=model, api_key=self.api_key)
        self.threat_intel = ThreatIntelAgent(model=model, api_key=self.api_key)
        self.log_analysis = LogAnalysisAgent(model=model, api_key=self.api_key)
        self.ir = IncidentResponseAgent(model=model, api_key=self.api_key)
        self.reporting = ReportingAgent(model=model, api_key=self.api_key)

    def process_alert(
        self,
        alert: Alert,
        log_entries: List[dict] = None,
        status_callback: Callable[[str, str], None] = None,
    ) -> Optional[Incident]:
        """
        Process a single alert through the full SOC pipeline.
        Returns an Incident if a true positive, None if false positive.
        """
        log_entries = log_entries or []

        def _status(agent_name: str, msg: str):
            if status_callback:
                status_callback(agent_name, msg)

        # ── Step 1: Alert Triage ────────────────────────────────────────────
        _status("TriageAgent", f"Triaging alert {alert.id}: {alert.alert_type}")
        triage_result = self.triage.triage(
            alert,
            status_callback=lambda msg: _status("TriageAgent", msg),
        )

        if triage_result["false_positive"]:
            _status("TriageAgent", f"Alert {alert.id} classified as FALSE POSITIVE — skipping")
            return None

        priority = triage_result["priority"]
        _status("TriageAgent", f"Alert {alert.id} → {priority} true positive")

        # In interactive mode, P1 incidents require human confirmation
        if self.interactive and priority == "P1":
            _status("Orchestrator", f"P1 incident detected. Triage summary:\n{triage_result['summary']}")
            confirm = input("\nProceed with full investigation? (y/n): ").strip().lower()
            if confirm != "y":
                _status("Orchestrator", "Investigation skipped by operator")
                return None

        # ── Step 2: Threat Intelligence ─────────────────────────────────────
        _status("ThreatIntelAgent", f"Running threat intel analysis for alert {alert.id}")
        threat_intel_result = self.threat_intel.analyze(
            alert,
            status_callback=lambda msg: _status("ThreatIntelAgent", msg),
        )

        # ── Step 3: Log Analysis ─────────────────────────────────────────────
        _status("LogAnalysisAgent", f"Analyzing {len(log_entries)} log entries")
        log_result = self.log_analysis.analyze(
            alert,
            log_entries,
            status_callback=lambda msg: _status("LogAnalysisAgent", msg),
        )

        # ── Step 4: Create Incident ──────────────────────────────────────────
        affected_assets = list(set(
            ([alert.hostname] if alert.hostname else []) +
            log_result.get("affected_hosts", []) +
            ([alert.source_ip] if alert.source_ip else [])
        ))

        has_exfil = "exfil" in alert.alert_type.lower() or "data" in alert.alert_type.lower()
        risk_result = calculate_risk_score(
            severity=alert.severity,
            ttp_count=len(threat_intel_result.ttps),
            affected_assets=len(affected_assets),
            has_exfil=has_exfil,
        )

        incident = Incident(
            alerts=[alert],
            priority=priority,
            status="investigating",
            classification=alert.alert_type,
            ttps=threat_intel_result.ttps,
            iocs=threat_intel_result.iocs,
            affected_assets=affected_assets,
            risk_score=risk_result["risk_score"],
            triage_summary=triage_result["summary"],
            threat_intel_summary=f"Threat type: {threat_intel_result.threat_type}. Actor: {threat_intel_result.threat_actor or 'Unknown'}. TTPs: {', '.join(threat_intel_result.ttps)}",
            log_analysis_summary=log_result["summary"][:500] if log_result.get("summary") else None,
        )

        # ── Step 5: Incident Response Planning ──────────────────────────────
        _status("IRAgent", f"Generating response playbook for {incident.id}")
        ir_result = self.ir.respond(
            incident,
            status_callback=lambda msg: _status("IRAgent", msg),
        )
        incident.playbook = ir_result["response_plan"]
        incident.response_summary = ir_result["response_plan"][:500]

        # ── Step 6: Final Report ─────────────────────────────────────────────
        _status("ReportingAgent", f"Generating incident report for {incident.id}")
        report_result = self.reporting.report(
            incident,
            status_callback=lambda msg: _status("ReportingAgent", msg),
        )
        incident.final_report = report_result["full_report"]
        incident.executive_summary = report_result["executive_summary"]
        incident.status = "contained"

        self.incidents.append(incident)
        _status("Orchestrator", f"Incident {incident.id} processing complete")
        return incident

    def process_alerts_from_file(
        self,
        alert_file: str,
        log_file: Optional[str] = None,
        status_callback: Callable[[str, str], None] = None,
    ) -> List[Incident]:
        """Load and process alerts from JSON file."""
        with open(alert_file) as f:
            alerts_data = json.load(f)

        log_entries = []
        if log_file and os.path.exists(log_file):
            with open(log_file) as f:
                log_entries = json.load(f)

        incidents = []
        for alert_data in alerts_data:
            alert = Alert.from_dict(alert_data)
            incident = self.process_alert(alert, log_entries, status_callback)
            if incident:
                incidents.append(incident)

        return incidents

    def get_soc_metrics(self) -> dict:
        """Return SOC KPI metrics for all processed incidents."""
        return self.reporting.generate_soc_metrics(self.incidents)
