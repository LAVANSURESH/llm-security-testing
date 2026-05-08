"""Incident Response Agent — generates playbooks, containment steps, and remediation guidance."""

import json
import sys
import os
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from soc.agents.base_agent import BaseAgent
from soc.models.incident import Incident
from soc.tools.response_tools import get_playbook, get_containment_steps, estimate_impact

SYSTEM_PROMPT = """You are a senior Incident Response (IR) specialist with 15+ years of experience.
You have led responses to major breaches at Fortune 500 companies.

Your responsibilities:
1. Generate detailed, actionable incident response playbooks
2. Recommend immediate containment actions
3. Provide step-by-step remediation guidance
4. Estimate business impact
5. Ensure regulatory compliance requirements are addressed

Your playbooks must follow NIST SP 800-61 incident response lifecycle:
Preparation → Detection → Containment → Eradication → Recovery → Post-Incident

Be specific, actionable, and prioritize by impact. Think like a first responder."""

TOOLS = [
    {
        "name": "get_playbook",
        "description": "Generate a structured incident response playbook for the attack type",
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_type": {"type": "string", "description": "Type of attack (ransomware, brute_force, data_exfiltration, lateral_movement)"},
                "severity": {"type": "string", "description": "Incident severity (critical, high, medium, low)"},
                "ttps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of MITRE ATT&CK TTP IDs involved",
                },
            },
            "required": ["attack_type", "severity"],
        },
    },
    {
        "name": "get_containment_steps",
        "description": "Get specific containment steps for affected assets",
        "input_schema": {
            "type": "object",
            "properties": {
                "affected_assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of affected asset names/types",
                },
                "attack_type": {"type": "string", "description": "Type of attack for context"},
            },
            "required": ["affected_assets", "attack_type"],
        },
    },
    {
        "name": "estimate_impact",
        "description": "Estimate the business impact of the incident",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "Incident severity"},
                "affected_assets": {"type": "integer", "description": "Number of affected assets"},
                "data_exfiltrated": {"type": "boolean", "description": "Whether data was exfiltrated"},
                "systems_down": {"type": "integer", "description": "Number of systems that are down"},
            },
            "required": ["severity", "affected_assets", "data_exfiltrated", "systems_down"],
        },
    },
]


def _tool_executor(tool_name: str, tool_input: dict):
    if tool_name == "get_playbook":
        return get_playbook(
            tool_input["attack_type"],
            tool_input.get("severity", "high"),
            tool_input.get("ttps", []),
        )
    if tool_name == "get_containment_steps":
        return get_containment_steps(tool_input["affected_assets"], tool_input["attack_type"])
    if tool_name == "estimate_impact":
        return estimate_impact(
            tool_input["severity"],
            tool_input["affected_assets"],
            tool_input["data_exfiltrated"],
            tool_input["systems_down"],
        )
    return {"error": f"Unknown tool: {tool_name}"}


class IncidentResponseAgent(BaseAgent):
    def respond(self, incident: Incident, status_callback: Optional[Callable] = None) -> dict:
        """Generate incident response plan for the given incident."""
        incident_data = json.dumps(incident.to_dict(), indent=2)

        user_message = f"""Generate a complete incident response plan for this incident:

{incident_data}

Please:
1. Get the appropriate playbook for this attack type (use get_playbook tool)
2. Get containment steps for the affected assets (use get_containment_steps tool)
3. Estimate the business impact (use estimate_impact tool)
4. Provide your complete IR recommendations including:
   - Immediate actions (next 15 minutes)
   - Containment strategy
   - Evidence preservation requirements
   - Communication plan (who to notify and when)
   - Recovery timeline estimate"""

        result = self.run(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            tools=TOOLS,
            tool_executor=_tool_executor,
            status_callback=status_callback,
        )

        return {
            "response_plan": result,
            "incident_id": incident.id,
            "priority": incident.priority,
        }
