"""Incident response playbook generation and remediation tools."""

from typing import List

# MITRE-aligned playbook templates by attack category
PLAYBOOK_TEMPLATES = {
    "ransomware": {
        "immediate_actions": [
            "ISOLATE affected systems from the network immediately",
            "Disable all network interfaces on compromised hosts",
            "Revoke all active sessions and tokens for affected users",
            "Alert executive team and legal/compliance",
        ],
        "investigation": [
            "Identify patient zero and initial infection vector",
            "Determine ransomware family using file extensions and ransom note",
            "Map lateral movement paths using EDR telemetry",
            "Identify all encrypted files and affected systems",
            "Preserve forensic evidence (memory dump, disk image)",
        ],
        "containment": [
            "Block C2 IPs/domains at firewall and DNS level",
            "Disable compromised accounts",
            "Segment affected network zones",
            "Stop backup jobs to prevent encrypting backups",
        ],
        "eradication": [
            "Remove malware artifacts from all infected systems",
            "Patch exploited vulnerability",
            "Reset all credentials across the environment",
            "Rebuild compromised systems from known-good images",
        ],
        "recovery": [
            "Restore from clean backups (verify backup integrity first)",
            "Re-enable systems in isolated environment for validation",
            "Monitor for re-infection indicators",
            "Gradually restore network connectivity with enhanced monitoring",
        ],
        "post_incident": [
            "Complete root cause analysis",
            "Update firewall and EDR rules with new IOCs",
            "Conduct tabletop exercise based on findings",
            "File regulatory notifications if required (GDPR, HIPAA, etc.)",
        ],
    },
    "brute_force": {
        "immediate_actions": [
            "Block source IP(s) at perimeter firewall",
            "Lock targeted accounts temporarily",
            "Enable MFA for all accounts if not already enforced",
            "Alert account owners",
        ],
        "investigation": [
            "Determine if any logins succeeded",
            "Review all activity from successful sessions",
            "Identify all targeted accounts and systems",
            "Check for credential stuffing (leaked password database match)",
        ],
        "containment": [
            "Force password reset for targeted accounts",
            "Block attacking IP ranges at firewall",
            "Implement account lockout policy if not in place",
            "Enable geo-blocking for anomalous login regions",
        ],
        "eradication": [
            "Remove any unauthorized access granted",
            "Audit privileged account usage",
            "Review and clean up stale/unused accounts",
        ],
        "recovery": [
            "Re-enable accounts after password reset and MFA enrollment",
            "Monitor accounts for 30 days post-incident",
        ],
        "post_incident": [
            "Implement rate limiting and CAPTCHA on login pages",
            "Deploy credential monitoring service",
            "Review password policy strength requirements",
        ],
    },
    "data_exfiltration": {
        "immediate_actions": [
            "Block outbound connection to suspected C2/exfil destination",
            "Isolate systems involved in data transfer",
            "Preserve network flow logs and PCAP evidence",
            "Initiate legal hold procedures",
        ],
        "investigation": [
            "Determine what data was exfiltrated (classify sensitivity)",
            "Identify exfiltration mechanism (cloud storage, DNS, HTTP)",
            "Quantify volume of data transferred",
            "Identify all compromised user accounts involved",
            "Determine dwell time (how long attacker had access)",
        ],
        "containment": [
            "Block exfiltration channels at proxy/firewall",
            "Disable compromised accounts",
            "Revoke API keys and OAuth tokens",
            "Enable DLP rules for sensitive data keywords",
        ],
        "eradication": [
            "Remove attacker persistence mechanisms",
            "Patch exploited vulnerabilities",
            "Rotate all secrets and credentials",
        ],
        "recovery": [
            "Restore affected systems",
            "Re-enable user accounts with new credentials and MFA",
            "Enhanced monitoring for 90 days",
        ],
        "post_incident": [
            "Notify affected customers/users if PII was exposed",
            "File regulatory breach notifications (GDPR 72-hour window, etc.)",
            "Implement data classification and DLP controls",
            "Conduct security awareness training",
        ],
    },
    "lateral_movement": {
        "immediate_actions": [
            "Isolate affected network segments",
            "Disable compromised credentials",
            "Block SMB/RDP/WMI from untrusted sources",
        ],
        "investigation": [
            "Map all systems the attacker accessed",
            "Identify initial compromise vector",
            "Review authentication logs for pass-the-hash/pass-the-ticket",
            "Identify all compromised credentials",
        ],
        "containment": [
            "Implement network micro-segmentation",
            "Reset all domain admin passwords",
            "Enable Protected Users security group in AD",
            "Deploy honeypot credentials to detect further movement",
        ],
        "eradication": [
            "Remove attacker from all accessed systems",
            "Clean up persistence mechanisms",
            "Patch vulnerabilities used for lateral movement",
        ],
        "recovery": [
            "Rebuild compromised systems",
            "Restore from clean backups",
            "Re-provision credentials across environment",
        ],
        "post_incident": [
            "Implement least-privilege access model",
            "Deploy PAM (Privileged Access Management) solution",
            "Enable credential guard on Windows systems",
        ],
    },
    "default": {
        "immediate_actions": [
            "Isolate affected systems",
            "Preserve evidence (logs, memory, disk)",
            "Notify security team and management",
            "Document initial findings",
        ],
        "investigation": [
            "Identify all affected systems and users",
            "Determine attack vector and timeline",
            "Collect and preserve forensic evidence",
            "Identify all attacker TTPs",
        ],
        "containment": [
            "Block malicious IPs/domains",
            "Disable compromised accounts",
            "Patch exploited vulnerabilities",
        ],
        "eradication": [
            "Remove malware and attacker artifacts",
            "Reset compromised credentials",
            "Close initial access vector",
        ],
        "recovery": [
            "Restore systems from clean backups",
            "Re-enable services with enhanced monitoring",
            "Validate security controls",
        ],
        "post_incident": [
            "Complete root cause analysis",
            "Update detection rules with new IOCs",
            "Review and improve security controls",
            "Document lessons learned",
        ],
    },
}

CONTAINMENT_BY_ASSET = {
    "server": ["Isolate VM/host at hypervisor level", "Take memory snapshot", "Block all outbound traffic", "Disable service accounts"],
    "workstation": ["Quarantine via EDR", "Disable network adapter", "Force logout all sessions", "Revoke user certificates"],
    "network_device": ["Apply ACL to block suspicious traffic", "Capture interface traffic", "Disable compromised ports", "Rotate device credentials"],
    "cloud": ["Revoke IAM credentials", "Stop EC2/VM instance", "Enable GuardDuty/Security Center", "Enable CloudTrail/Audit logging"],
    "database": ["Revoke application credentials", "Enable query auditing", "Restrict connection sources", "Export audit logs"],
}


def get_playbook(attack_type: str, severity: str, ttps: List[str]) -> dict:
    """Generate an incident response playbook for the given attack type."""
    # Map attack type to template key
    template_key = "default"
    attack_lower = attack_type.lower()
    if "ransom" in attack_lower or "T1486" in ttps:
        template_key = "ransomware"
    elif "brute" in attack_lower or "credential" in attack_lower or "T1110" in ttps:
        template_key = "brute_force"
    elif "exfil" in attack_lower or "data" in attack_lower or "T1041" in ttps:
        template_key = "data_exfiltration"
    elif "lateral" in attack_lower or "T1021" in " ".join(ttps):
        template_key = "lateral_movement"

    template = PLAYBOOK_TEMPLATES.get(template_key, PLAYBOOK_TEMPLATES["default"])

    # Build playbook markdown
    playbook_md = f"# Incident Response Playbook: {attack_type.upper()}\n"
    playbook_md += f"**Severity**: {severity.upper()} | **TTPs**: {', '.join(ttps) if ttps else 'Unknown'}\n\n"

    sections = [
        ("🚨 Immediate Actions (0-15 min)", "immediate_actions"),
        ("🔍 Investigation (15 min - 4 hrs)", "investigation"),
        ("🔒 Containment", "containment"),
        ("🧹 Eradication", "eradication"),
        ("✅ Recovery", "recovery"),
        ("📋 Post-Incident Activities", "post_incident"),
    ]

    for section_title, key in sections:
        steps = template.get(key, [])
        playbook_md += f"## {section_title}\n"
        for i, step in enumerate(steps, 1):
            playbook_md += f"{i}. {step}\n"
        playbook_md += "\n"

    return {
        "playbook_type": template_key,
        "severity": severity,
        "ttps": ttps,
        "playbook_markdown": playbook_md,
        "step_count": sum(len(template.get(k, [])) for _, k in sections),
    }


def get_containment_steps(affected_assets: List[str], attack_type: str) -> dict:
    """Get specific containment steps for affected assets."""
    steps = []
    for asset in affected_assets:
        asset_lower = asset.lower()
        asset_type = "server"
        if "workstation" in asset_lower or "laptop" in asset_lower or "desktop" in asset_lower:
            asset_type = "workstation"
        elif "router" in asset_lower or "switch" in asset_lower or "firewall" in asset_lower:
            asset_type = "network_device"
        elif "cloud" in asset_lower or "aws" in asset_lower or "azure" in asset_lower or "gcp" in asset_lower:
            asset_type = "cloud"
        elif "db" in asset_lower or "database" in asset_lower or "sql" in asset_lower:
            asset_type = "database"

        asset_steps = CONTAINMENT_BY_ASSET.get(asset_type, CONTAINMENT_BY_ASSET["server"])
        steps.append({
            "asset": asset,
            "asset_type": asset_type,
            "containment_steps": asset_steps,
        })

    return {
        "asset_count": len(affected_assets),
        "containment_plan": steps,
        "estimated_time_minutes": len(affected_assets) * 15,
    }


def estimate_impact(severity: str, affected_assets: int, data_exfiltrated: bool, systems_down: int) -> dict:
    """Estimate the business impact of an incident."""
    severity_multipliers = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    multiplier = severity_multipliers.get(severity.lower(), 2)

    estimated_cost_low = affected_assets * 5000 * multiplier
    estimated_cost_high = affected_assets * 50000 * multiplier

    if data_exfiltrated:
        estimated_cost_low *= 2
        estimated_cost_high *= 3

    impact_areas = []
    if systems_down > 0:
        impact_areas.append(f"Operational: {systems_down} system(s) down")
    if data_exfiltrated:
        impact_areas.append("Data Breach: Potential regulatory fines and notification costs")
    if affected_assets > 5:
        impact_areas.append("Business Continuity: Significant operational disruption")
    if severity in ("critical", "high"):
        impact_areas.append("Reputational: Customer trust and brand damage risk")

    return {
        "severity": severity,
        "affected_assets": affected_assets,
        "systems_down": systems_down,
        "data_exfiltrated": data_exfiltrated,
        "estimated_cost_range": f"${estimated_cost_low:,} - ${estimated_cost_high:,}",
        "impact_areas": impact_areas,
        "requires_regulatory_notification": data_exfiltrated,
        "estimated_recovery_hours": systems_down * 4 + affected_assets * 2,
    }
