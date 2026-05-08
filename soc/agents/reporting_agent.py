"""Reporting Agent — generates SOC incident reports and executive summaries."""

import json
import sys
import os
from typing import Callable, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from soc.agents.base_agent import BaseAgent
from soc.models.incident import Incident
from soc.tools.analysis_tools import calculate_risk_score

SYSTEM_PROMPT = """You are a SOC Manager and security reporting specialist.
You produce two types of reports:

1. **Technical Incident Report**: Detailed for the security team
   - Full timeline of events
   - Technical indicators (TTPs, IOCs, affected systems)
   - Root cause analysis
   - Detailed remediation steps
   - Lessons learned

2. **Executive Summary**: For C-suite / board level
   - Business impact in plain language (no jargon)
   - What happened, what was affected, what was done
   - Risk exposure and regulatory implications
   - Key decisions required from leadership
   - Recommended investments to prevent recurrence

Be factual, concise, and ensure each report is appropriate for its audience."""

TOOLS = [
    {
        "name": "calculate_risk_score",
        "description": "Calculate a numerical risk score (0-10) for an incident",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "Incident severity (critical/high/medium/low)"},
                "ttp_count": {"type": "integer", "description": "Number of MITRE TTPs involved"},
                "affected_assets": {"type": "integer", "description": "Number of affected assets"},
                "has_exfil": {"type": "boolean", "description": "Whether data exfiltration occurred"},
            },
            "required": ["severity", "ttp_count", "affected_assets", "has_exfil"],
        },
    },
]


def _tool_executor(tool_name: str, tool_input: dict):
    if tool_name == "calculate_risk_score":
        return calculate_risk_score(
            tool_input["severity"],
            tool_input["ttp_count"],
            tool_input["affected_assets"],
            tool_input["has_exfil"],
        )
    return {"error": f"Unknown tool: {tool_name}"}


class ReportingAgent(BaseAgent):
    def report(self, incident: Incident, status_callback: Optional[Callable] = None) -> dict:
        """Generate full incident report and executive summary."""
        # Build comprehensive incident context
        incident_data = json.dumps(incident.to_dict(), indent=2)
        has_exfil = "exfil" in incident.classification.lower() or "data" in incident.classification.lower()

        user_message = f"""Generate comprehensive reports for this security incident:

{incident_data}

## Additional Context:
- Triage Assessment: {incident.triage_summary or 'See incident data'}
- Threat Intel: {incident.threat_intel_summary or 'See TTPs and IOCs in incident data'}
- Log Analysis: {incident.log_analysis_summary or 'See timeline in incident data'}
- Response Plan: {incident.response_summary or 'See incident data'}

Please:
1. Calculate the risk score first (use calculate_risk_score tool)
2. Write a complete **Technical Incident Report** with:
   - Incident ID, date, classification, risk score
   - Executive summary (3 sentences)
   - Detailed timeline
   - Technical indicators (TTPs with names, IOCs)
   - Affected systems and users
   - Root cause
   - Full remediation steps

3. Write a concise **Executive Summary** (max 300 words) covering:
   - What happened (plain language)
   - Business impact
   - Immediate actions taken
   - Regulatory implications
   - Recommended investments

Separate the two sections clearly with headers."""

        result = self.run(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            tools=TOOLS,
            tool_executor=_tool_executor,
            status_callback=status_callback,
        )

        # Split technical report from executive summary
        exec_summary = ""
        tech_report = result
        if "Executive Summary" in result:
            parts = result.split("Executive Summary", 1)
            tech_report = parts[0].strip()
            exec_summary = "Executive Summary" + parts[1].strip()

        return {
            "full_report": result,
            "technical_report": tech_report,
            "executive_summary": exec_summary,
            "incident_id": incident.id,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def generate_soc_metrics(self, incidents: List[Incident]) -> dict:
        """Generate SOC KPI metrics from a list of incidents."""
        if not incidents:
            return {"message": "No incidents to analyze"}

        priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        status_counts = {"open": 0, "investigating": 0, "contained": 0, "resolved": 0}
        total_risk = 0.0

        for inc in incidents:
            priority_counts[inc.priority] = priority_counts.get(inc.priority, 0) + 1
            status_counts[inc.status] = status_counts.get(inc.status, 0) + 1
            total_risk += inc.risk_score

        return {
            "total_incidents": len(incidents),
            "by_priority": priority_counts,
            "by_status": status_counts,
            "average_risk_score": round(total_risk / len(incidents), 1),
            "critical_incidents": priority_counts.get("P1", 0),
            "open_incidents": status_counts.get("open", 0) + status_counts.get("investigating", 0),
        }
