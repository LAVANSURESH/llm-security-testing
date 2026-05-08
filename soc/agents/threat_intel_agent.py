"""Threat Intelligence Agent — maps to MITRE ATT&CK, correlates IOCs, identifies threat actors."""

import json
import sys
import os
from typing import Callable, Optional, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from soc.agents.base_agent import BaseAgent
from soc.models.alert import Alert
from soc.models.threat_intel import ThreatIntel
from soc.tools.search_tools import (
    get_mitre_ttp, search_threat_intel, correlate_iocs,
    extract_iocs_from_text, enrich_ip
)

SYSTEM_PROMPT = """You are a senior Threat Intelligence analyst with deep knowledge of:
- MITRE ATT&CK framework (tactics, techniques, sub-techniques)
- Threat actor groups and their TTPs (APT28, APT29, APT41, Lazarus, etc.)
- Indicators of Compromise (IPs, domains, hashes, URLs)
- Attack campaigns and malware families

Your job is to:
1. Extract all IOCs from the alert data
2. Map the attack to MITRE ATT&CK TTPs
3. Correlate IOCs with known threat actors
4. Assess the threat actor and campaign if identifiable
5. Provide actionable threat intelligence

Use the available tools to enrich your analysis."""

TOOLS = [
    {
        "name": "get_mitre_ttp",
        "description": "Get details about a MITRE ATT&CK technique",
        "input_schema": {
            "type": "object",
            "properties": {
                "ttp_id": {"type": "string", "description": "MITRE TTP ID (e.g. T1078, T1110.003)"}
            },
            "required": ["ttp_id"],
        },
    },
    {
        "name": "search_threat_intel",
        "description": "Check if an IOC is in the threat intelligence database",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IP, domain, or hash to look up"}
            },
            "required": ["ioc"],
        },
    },
    {
        "name": "correlate_iocs",
        "description": "Correlate multiple IOCs to find connections and threat actor attribution",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_list": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of IOCs to correlate",
                }
            },
            "required": ["ioc_list"],
        },
    },
    {
        "name": "extract_iocs_from_text",
        "description": "Extract IPs, domains, and hashes from a text string",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to extract IOCs from"}
            },
            "required": ["text"],
        },
    },
    {
        "name": "enrich_ip",
        "description": "Enrich an IP with geolocation and reputation",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP to enrich"}
            },
            "required": ["ip"],
        },
    },
]


def _tool_executor(tool_name: str, tool_input: dict):
    if tool_name == "get_mitre_ttp":
        return get_mitre_ttp(tool_input["ttp_id"])
    if tool_name == "search_threat_intel":
        return search_threat_intel(tool_input["ioc"])
    if tool_name == "correlate_iocs":
        return correlate_iocs(tool_input["ioc_list"])
    if tool_name == "extract_iocs_from_text":
        return extract_iocs_from_text(tool_input["text"])
    if tool_name == "enrich_ip":
        return enrich_ip(tool_input["ip"])
    return {"error": f"Unknown tool: {tool_name}"}


class ThreatIntelAgent(BaseAgent):
    def analyze(self, alert: Alert, status_callback: Optional[Callable] = None) -> ThreatIntel:
        """Analyze an alert for threat intelligence and return ThreatIntel object."""
        alert_data = json.dumps(alert.to_dict(), indent=2)
        user_message = f"""Perform threat intelligence analysis on this alert:

{alert_data}

Provide:
1. List of all IOCs (IPs, domains, hashes) extracted
2. MITRE ATT&CK TTPs mapped (use TTP IDs like T1078, T1110.003)
3. Threat actor assessment if attributable
4. Confidence score (0-100%)
5. Key recommendations for the SOC team"""

        result = self.run(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            tools=TOOLS,
            tool_executor=_tool_executor,
            status_callback=status_callback,
        )

        # Extract TTPs from response
        import re
        ttp_pattern = r'T\d{4}(?:\.\d{3})?'
        ttps = list(set(re.findall(ttp_pattern, result)))

        # Extract IOCs
        from soc.tools.search_tools import extract_iocs_from_text
        extracted = extract_iocs_from_text(result)
        iocs = extracted["ips"] + extracted["domains"] + extracted["md5_hashes"]

        # Add IOCs from original alert
        if alert.source_ip:
            iocs.append(alert.source_ip)
        if alert.dest_ip:
            iocs.append(alert.dest_ip)
        iocs = list(set(iocs))

        # Detect threat actor
        threat_actor = None
        for actor in ["APT28", "APT29", "APT41", "Lazarus", "LockBit", "Conti", "REvil", "FIN7"]:
            if actor.lower() in result.lower():
                threat_actor = actor
                break

        confidence = 0.7
        if ttps:
            confidence += 0.1
        if threat_actor:
            confidence += 0.1
        confidence = min(confidence, 0.99)

        return ThreatIntel(
            threat_type=alert.alert_type,
            ttps=ttps,
            iocs=iocs,
            confidence=confidence,
            threat_actor=threat_actor,
            recommendations=self._extract_recommendations(result),
        )

    def _extract_recommendations(self, text: str) -> List[str]:
        recs = []
        lines = text.split("\n")
        in_recs = False
        for line in lines:
            if "recommendation" in line.lower():
                in_recs = True
            elif in_recs and line.strip().startswith(("-", "*", "•")) or (in_recs and line.strip() and line.strip()[0].isdigit()):
                recs.append(line.strip().lstrip("-*•0123456789. "))
            elif in_recs and not line.strip():
                in_recs = False
        return recs[:5] if recs else ["Review and update firewall rules", "Monitor affected systems closely"]
