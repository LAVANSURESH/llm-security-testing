"""Alert Triage Agent — classifies severity, detects false positives, enriches alerts."""

import json
import sys
import os
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from soc.agents.base_agent import BaseAgent
from soc.models.alert import Alert
from soc.tools.search_tools import lookup_cve, search_threat_intel, enrich_ip

SYSTEM_PROMPT = """You are an experienced Tier-1 SOC analyst performing alert triage.
Your job is to:
1. Classify the alert priority (P1=Critical, P2=High, P3=Medium, P4=Low/Informational)
2. Determine if the alert is a true positive or false positive
3. Enrich the alert with threat intelligence context
4. Provide a concise triage summary with your assessment

Use the available tools to look up CVEs, check threat intelligence, and enrich IP addresses.
Base your priority on: severity, business impact, confidence, and threat context.

Return a structured assessment at the end."""

TOOLS = [
    {
        "name": "lookup_cve",
        "description": "Look up details about a specific CVE vulnerability",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID (e.g. CVE-2021-44228)"}
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_threat_intel",
        "description": "Check if an IP, domain, or hash is known malicious in threat intelligence",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IP address, domain, or hash to check"}
            },
            "required": ["ioc"],
        },
    },
    {
        "name": "enrich_ip",
        "description": "Enrich an IP address with geolocation and reputation data",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to enrich"}
            },
            "required": ["ip"],
        },
    },
]


def _tool_executor(tool_name: str, tool_input: dict):
    if tool_name == "lookup_cve":
        return lookup_cve(tool_input["cve_id"])
    if tool_name == "search_threat_intel":
        return search_threat_intel(tool_input["ioc"])
    if tool_name == "enrich_ip":
        return enrich_ip(tool_input["ip"])
    return {"error": f"Unknown tool: {tool_name}"}


class TriageAgent(BaseAgent):
    def triage(self, alert: Alert, status_callback: Optional[Callable] = None) -> dict:
        """Triage an alert and return priority, false positive verdict, and summary."""
        alert_context = json.dumps(alert.to_dict(), indent=2)
        user_message = f"""Triage this security alert:

{alert_context}

Provide:
1. Priority: P1/P2/P3/P4
2. True positive or false positive assessment with confidence (0-100%)
3. Enrichment from threat intelligence
4. Triage summary (2-3 sentences)
5. Recommended next action"""

        result = self.run(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            tools=TOOLS,
            tool_executor=_tool_executor,
            status_callback=status_callback,
        )

        # Parse priority from response
        priority = "P3"
        for p in ["P1", "P2", "P3", "P4"]:
            if p in result:
                priority = p
                break

        false_positive = any(kw in result.lower() for kw in ["false positive", "benign", "not malicious", "fp"])

        return {
            "priority": priority,
            "false_positive": false_positive,
            "summary": result,
            "alert_id": alert.id,
        }
