"""Log analysis, anomaly detection, and event correlation tools for SOC agents."""

import json
import re
from datetime import datetime
from typing import List, Dict, Any


def parse_log_entry(raw_log: str) -> dict:
    """Parse a raw log string into structured fields."""
    # Try JSON first
    try:
        parsed = json.loads(raw_log)
        return {"success": True, "format": "json", "entry": parsed}
    except (json.JSONDecodeError, TypeError):
        pass

    # Try syslog format
    syslog_pattern = r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)'
    m = re.match(syslog_pattern, str(raw_log))
    if m:
        return {
            "success": True,
            "format": "syslog",
            "entry": {
                "timestamp": m.group(1),
                "host": m.group(2),
                "process": m.group(3),
                "message": m.group(4),
            },
        }

    # Try Apache/Nginx combined log format
    apache_pattern = r'(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)'
    m = re.match(apache_pattern, str(raw_log))
    if m:
        return {
            "success": True,
            "format": "apache_combined",
            "entry": {
                "client_ip": m.group(1),
                "user": m.group(2),
                "timestamp": m.group(3),
                "request": m.group(4),
                "status_code": int(m.group(5)),
                "bytes": int(m.group(6)),
            },
        }

    # Fallback: return as raw text
    return {"success": True, "format": "raw", "entry": {"raw": str(raw_log)}}


def detect_anomalies(log_entries: List[Dict], context: str = "") -> dict:
    """Detect anomalies in a list of log entries."""
    anomalies = []

    # Brute force detection: many failed logins
    failed_logins = [e for e in log_entries if _is_failed_login(e)]
    if len(failed_logins) >= 5:
        ips = list(set(e.get("source_ip", e.get("client_ip", "unknown")) for e in failed_logins))
        anomalies.append({
            "type": "brute_force",
            "severity": "high",
            "description": f"{len(failed_logins)} failed login attempts detected",
            "source_ips": ips,
            "count": len(failed_logins),
        })

    # After-hours access detection
    after_hours = [e for e in log_entries if _is_after_hours(e)]
    if after_hours:
        anomalies.append({
            "type": "after_hours_access",
            "severity": "medium",
            "description": f"{len(after_hours)} access events outside business hours",
            "count": len(after_hours),
        })

    # Large data transfer
    large_transfers = [e for e in log_entries if _is_large_transfer(e)]
    if large_transfers:
        total_bytes = sum(e.get("bytes_sent", e.get("bytes", 0)) for e in large_transfers)
        anomalies.append({
            "type": "large_data_transfer",
            "severity": "high",
            "description": f"Unusually large data transfer detected: {total_bytes:,} bytes",
            "total_bytes": total_bytes,
            "event_count": len(large_transfers),
        })

    # Privilege escalation indicators
    priv_esc = [e for e in log_entries if _is_priv_escalation(e)]
    if priv_esc:
        anomalies.append({
            "type": "privilege_escalation",
            "severity": "critical",
            "description": f"{len(priv_esc)} privilege escalation indicators found",
            "count": len(priv_esc),
        })

    # Lateral movement indicators
    lateral = [e for e in log_entries if _is_lateral_movement(e)]
    if lateral:
        anomalies.append({
            "type": "lateral_movement",
            "severity": "high",
            "description": f"{len(lateral)} lateral movement indicators detected (SMB/RDP/PsExec)",
            "count": len(lateral),
        })

    return {
        "total_events": len(log_entries),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "risk_level": _calculate_risk_level(anomalies),
    }


def correlate_events(events: List[Dict]) -> dict:
    """Correlate security events to identify attack chains."""
    if not events:
        return {"correlation_found": False, "attack_chain": [], "message": "No events to correlate"}

    # Sort by timestamp
    sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))

    # Look for attack progression patterns
    event_types = [e.get("type", e.get("event_type", "unknown")) for e in sorted_events]
    attack_chain = []

    # Recon → Initial Access → Execution → Persistence → Exfil
    stages = {
        "recon": ["port_scan", "vulnerability_scan", "reconnaissance"],
        "initial_access": ["brute_force", "phishing", "exploit", "login_failure", "sql_injection"],
        "execution": ["command_execution", "malware", "script_execution"],
        "persistence": ["new_service", "scheduled_task", "registry_modification"],
        "lateral_movement": ["lateral_movement", "smb_access", "rdp_login"],
        "exfiltration": ["data_exfil", "large_data_transfer", "c2_communication"],
    }

    detected_stages = []
    for stage, indicators in stages.items():
        for et in event_types:
            if any(ind in et.lower() for ind in indicators):
                if stage not in detected_stages:
                    detected_stages.append(stage)
                    attack_chain.append({"stage": stage, "event_type": et})
                break

    return {
        "correlation_found": len(detected_stages) > 1,
        "detected_stages": detected_stages,
        "attack_chain": attack_chain,
        "attack_progression": " → ".join(detected_stages) if detected_stages else "Unknown",
        "is_multi_stage": len(detected_stages) >= 3,
        "total_events": len(events),
    }


def build_timeline(events: List[Dict]) -> dict:
    """Build a chronological incident timeline from events."""
    sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
    timeline = []

    for event in sorted_events:
        entry = {
            "timestamp": event.get("timestamp", "unknown"),
            "event": event.get("description", event.get("message", str(event))),
            "source": event.get("source", event.get("host", "unknown")),
            "severity": event.get("severity", "info"),
        }
        timeline.append(entry)

    return {
        "timeline": timeline,
        "start_time": timeline[0]["timestamp"] if timeline else None,
        "end_time": timeline[-1]["timestamp"] if timeline else None,
        "duration_events": len(timeline),
    }


def calculate_risk_score(severity: str, ttp_count: int, affected_assets: int, has_exfil: bool) -> dict:
    """Calculate a numerical risk score (0-10) for an incident."""
    base_scores = {"critical": 8.0, "high": 6.0, "medium": 4.0, "low": 2.0}
    score = base_scores.get(severity.lower(), 4.0)

    # Adjust for TTP breadth
    score += min(ttp_count * 0.2, 1.0)

    # Adjust for blast radius
    score += min(affected_assets * 0.1, 0.5)

    # Exfiltration is highest severity multiplier
    if has_exfil:
        score = min(score * 1.3, 10.0)

    return {
        "risk_score": round(min(score, 10.0), 1),
        "risk_level": "CRITICAL" if score >= 8 else "HIGH" if score >= 6 else "MEDIUM" if score >= 4 else "LOW",
        "factors": {
            "base_severity": severity,
            "ttp_count": ttp_count,
            "affected_assets": affected_assets,
            "exfiltration_detected": has_exfil,
        },
    }


# --- Helper functions ---

def _is_failed_login(entry: dict) -> bool:
    msg = str(entry).lower()
    return any(kw in msg for kw in ["failed login", "authentication failed", "invalid password", "login failure", "401"])


def _is_after_hours(entry: dict) -> bool:
    ts = entry.get("timestamp", "")
    try:
        if "T" in ts:
            hour = int(ts.split("T")[1][:2])
        elif ":" in ts:
            parts = ts.split(":")
            hour = int(parts[-3][-2:]) if len(parts) >= 3 else 12
        else:
            return False
        return hour < 7 or hour > 20
    except (ValueError, IndexError):
        return False


def _is_large_transfer(entry: dict) -> bool:
    bytes_val = entry.get("bytes_sent", entry.get("bytes", 0))
    try:
        return int(bytes_val) > 10_000_000  # 10MB threshold
    except (ValueError, TypeError):
        return False


def _is_priv_escalation(entry: dict) -> bool:
    msg = str(entry).lower()
    return any(kw in msg for kw in ["sudo", "privilege", "escalation", "runas", "setuid", "admin granted"])


def _is_lateral_movement(entry: dict) -> bool:
    msg = str(entry).lower()
    return any(kw in msg for kw in ["psexec", "smb", "lateral", "wmi", "rdp", "pass-the-hash"])


def _calculate_risk_level(anomalies: List[dict]) -> str:
    if any(a["severity"] == "critical" for a in anomalies):
        return "critical"
    if any(a["severity"] == "high" for a in anomalies):
        return "high"
    if any(a["severity"] == "medium" for a in anomalies):
        return "medium"
    return "low"
