"""Log Analysis Agent — analyzes security logs for anomalies and builds attack timelines."""

import json
import sys
import os
from typing import Callable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from soc.agents.base_agent import BaseAgent
from soc.models.alert import Alert
from soc.tools.analysis_tools import (
    parse_log_entry, detect_anomalies, correlate_events, build_timeline
)

SYSTEM_PROMPT = """You are a senior SOC analyst specializing in log analysis and threat hunting.
You analyze security logs from various sources:
- Authentication logs (Windows Event Log, Linux auth.log, LDAP)
- Web server logs (Apache, Nginx, IIS)
- Network flow logs (NetFlow, firewall logs)
- Endpoint logs (EDR, Sysmon)
- Cloud logs (CloudTrail, Azure Monitor)

Your job is to:
1. Parse and analyze log entries for suspicious patterns
2. Detect anomalies using statistical and behavioral analysis
3. Correlate events across sources to identify attack chains
4. Build a chronological attack timeline
5. Extract indicators of compromise from logs

Look for: brute force, privilege escalation, lateral movement, data exfiltration, C2 communication."""

TOOLS = [
    {
        "name": "parse_log_entry",
        "description": "Parse a raw log string into structured fields",
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_log": {"type": "string", "description": "Raw log string to parse"}
            },
            "required": ["raw_log"],
        },
    },
    {
        "name": "detect_anomalies",
        "description": "Detect anomalies in a list of log entries (brute force, after-hours, large transfers, privilege escalation)",
        "input_schema": {
            "type": "object",
            "properties": {
                "log_entries": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of structured log entries",
                },
                "context": {"type": "string", "description": "Alert context for better analysis"},
            },
            "required": ["log_entries"],
        },
    },
    {
        "name": "correlate_events",
        "description": "Correlate security events to identify multi-stage attack chains",
        "input_schema": {
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of security events to correlate",
                }
            },
            "required": ["events"],
        },
    },
    {
        "name": "build_timeline",
        "description": "Build a chronological incident timeline from events",
        "input_schema": {
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of events to build timeline from",
                }
            },
            "required": ["events"],
        },
    },
]


def _tool_executor(tool_name: str, tool_input: dict):
    if tool_name == "parse_log_entry":
        return parse_log_entry(tool_input["raw_log"])
    if tool_name == "detect_anomalies":
        return detect_anomalies(tool_input["log_entries"], tool_input.get("context", ""))
    if tool_name == "correlate_events":
        return correlate_events(tool_input["events"])
    if tool_name == "build_timeline":
        return build_timeline(tool_input["events"])
    return {"error": f"Unknown tool: {tool_name}"}


class LogAnalysisAgent(BaseAgent):
    def analyze(
        self,
        alert: Alert,
        log_entries: List[dict],
        status_callback: Optional[Callable] = None,
    ) -> dict:
        """Analyze logs related to an alert and return anomaly report with timeline."""
        alert_context = json.dumps(alert.to_dict(), indent=2)
        logs_context = json.dumps(log_entries[:20], indent=2)  # Limit to 20 entries

        user_message = f"""Analyze these security logs in the context of this alert:

## Alert Context:
{alert_context}

## Log Entries ({len(log_entries)} total, showing first 20):
{logs_context}

Please:
1. Parse and analyze the log entries for suspicious activity
2. Detect all anomalies (use detect_anomalies tool with the log entries)
3. Correlate events to identify attack chain (use correlate_events tool)
4. Build a timeline (use build_timeline tool)
5. Summarize your findings including: affected users/hosts, attack progression, and key evidence"""

        result = self.run(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            tools=TOOLS,
            tool_executor=_tool_executor,
            status_callback=status_callback,
        )

        # Extract affected assets from logs
        affected_hosts = set()
        affected_users = set()
        for entry in log_entries:
            if "hostname" in entry:
                affected_hosts.add(entry["hostname"])
            if "host" in entry:
                affected_hosts.add(entry["host"])
            if "user" in entry:
                affected_users.add(entry["user"])
            if "username" in entry:
                affected_users.add(entry["username"])

        return {
            "summary": result,
            "log_count": len(log_entries),
            "affected_hosts": list(affected_hosts),
            "affected_users": list(affected_users),
        }
