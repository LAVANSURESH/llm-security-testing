"""
SIEM Integration module — adapters to ingest alerts from common SIEM formats
and export incidents back to SIEM platforms.

Supported SIEM formats for alert ingestion:
  - Splunk (JSON via REST API or exported search results)
  - Elastic/SIEM (ECS format)
  - Microsoft Sentinel (Azure Monitor format)
  - QRadar (CEF / syslog format)
  - Generic CEF (Common Event Format)
  - Generic JSON (flat key-value)

Supported export destinations:
  - Splunk HEC (HTTP Event Collector)
  - Elasticsearch index
  - Webhook (generic POST)
  - File (JSON / NDJSON)
"""

import json
import re
import requests
from datetime import datetime
from typing import List, Optional

from soc.models.alert import Alert
from soc.models.incident import Incident


# ── Ingestion: SIEM → Alert ──────────────────────────────────────────────────

def from_splunk_event(event: dict) -> Alert:
    """Convert a Splunk JSON event to an Alert."""
    return Alert(
        id=event.get("_cd") or event.get("event_id", ""),
        timestamp=event.get("_time", datetime.utcnow().isoformat()),
        source="splunk",
        alert_type=event.get("signature", event.get("alert_type", "unknown")),
        severity=_normalize_severity(event.get("severity", event.get("priority", "medium"))),
        description=event.get("message", event.get("description", str(event))),
        raw_data=event,
        source_ip=event.get("src_ip", event.get("src", event.get("source_ip"))),
        dest_ip=event.get("dest_ip", event.get("dest", event.get("destination_ip"))),
        user=event.get("user", event.get("username")),
        hostname=event.get("host", event.get("hostname", event.get("dest_host"))),
    )


def from_elastic_ecs(doc: dict) -> Alert:
    """Convert an Elastic Common Schema (ECS) document to an Alert."""
    source = doc.get("source", {})
    destination = doc.get("destination", {})
    user = doc.get("user", {})
    event = doc.get("event", {})
    host = doc.get("host", {})

    return Alert(
        timestamp=doc.get("@timestamp", datetime.utcnow().isoformat()),
        source="elastic_siem",
        alert_type=event.get("category", ["unknown"])[0] if isinstance(event.get("category"), list) else event.get("category", "unknown"),
        severity=_normalize_severity(event.get("severity", "medium")),
        description=f"{event.get('action', 'unknown')} - {doc.get('message', '')}",
        raw_data=doc,
        source_ip=source.get("ip"),
        dest_ip=destination.get("ip"),
        user=user.get("name"),
        hostname=host.get("name"),
    )


def from_sentinel_alert(alert: dict) -> Alert:
    """Convert a Microsoft Sentinel alert to an Alert."""
    entities = alert.get("entities", [])
    source_ip = next((e.get("address") for e in entities if e.get("kind") == "Ip"), None)
    account = next((e.get("accountName") for e in entities if e.get("kind") == "Account"), None)
    hostname = next((e.get("hostName") for e in entities if e.get("kind") == "Host"), None)

    return Alert(
        id=alert.get("systemAlertId", ""),
        timestamp=alert.get("startTimeUtc", datetime.utcnow().isoformat()),
        source="microsoft_sentinel",
        alert_type=alert.get("alertType", "unknown").lower().replace(" ", "_"),
        severity=_normalize_severity(alert.get("severity", "Medium")),
        description=alert.get("description", alert.get("alertDisplayName", "")),
        raw_data=alert,
        source_ip=source_ip,
        user=account,
        hostname=hostname,
    )


def from_cef_syslog(cef_line: str) -> Alert:
    """Parse a CEF (Common Event Format) syslog line into an Alert."""
    # CEF format: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|[Extension]
    cef_pattern = r'CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)'
    m = re.match(cef_pattern, cef_line)

    if not m:
        return Alert(
            source="cef",
            alert_type="unknown",
            severity="medium",
            description=cef_line,
            raw_data={"raw": cef_line},
        )

    vendor = m.group(2)
    product = m.group(3)
    name = m.group(6)
    cef_severity = int(m.group(7))
    extensions_str = m.group(8)

    # Parse key=value extensions
    ext = {}
    for kv in re.findall(r'(\w+)=((?:[^\s\\]|\\.)+)', extensions_str):
        ext[kv[0]] = kv[1]

    severity_map = {range(0, 4): "low", range(4, 7): "medium", range(7, 9): "high", range(9, 11): "critical"}
    severity = "medium"
    for r, s in severity_map.items():
        if cef_severity in r:
            severity = s
            break

    return Alert(
        source=f"{vendor}/{product}",
        alert_type=name.lower().replace(" ", "_"),
        severity=severity,
        description=f"{vendor} {product}: {name}",
        raw_data={"cef": ext, "raw": cef_line},
        source_ip=ext.get("src", ext.get("sourceAddress")),
        dest_ip=ext.get("dst", ext.get("destinationAddress")),
        user=ext.get("suser", ext.get("sourceUserName")),
        hostname=ext.get("dhost", ext.get("destinationHostName")),
    )


def from_generic_json(data: dict) -> Alert:
    """Convert a generic flat JSON event to an Alert (best-effort mapping)."""
    # Try common field name variations
    def get_field(d, *keys):
        for k in keys:
            if k in d:
                return d[k]
        return None

    return Alert(
        id=get_field(data, "id", "event_id", "alert_id", "uuid") or "",
        timestamp=get_field(data, "timestamp", "time", "@timestamp", "event_time") or datetime.utcnow().isoformat(),
        source=get_field(data, "source", "device", "sensor", "product") or "unknown",
        alert_type=get_field(data, "alert_type", "type", "event_type", "category", "signature") or "unknown",
        severity=_normalize_severity(get_field(data, "severity", "priority", "risk_level") or "medium"),
        description=get_field(data, "description", "message", "msg", "summary", "details") or str(data),
        raw_data=data,
        source_ip=get_field(data, "source_ip", "src_ip", "src", "attacker_ip", "client_ip"),
        dest_ip=get_field(data, "dest_ip", "dst_ip", "dst", "target_ip"),
        user=get_field(data, "user", "username", "account", "actor"),
        hostname=get_field(data, "hostname", "host", "computer", "device_name"),
    )


def load_alerts_from_file(file_path: str, format: str = "auto") -> List[Alert]:
    """Load alerts from a file, auto-detecting or using specified format."""
    with open(file_path) as f:
        content = f.read().strip()

    alerts = []

    # NDJSON (one JSON object per line)
    if "\n{" in content or content.startswith("{"):
        events = [json.loads(line) for line in content.splitlines() if line.strip()]
    else:
        events = json.loads(content)
        if not isinstance(events, list):
            events = [events]

    for event in events:
        if format == "splunk":
            alerts.append(from_splunk_event(event))
        elif format == "elastic" or format == "ecs":
            alerts.append(from_elastic_ecs(event))
        elif format == "sentinel":
            alerts.append(from_sentinel_alert(event))
        else:
            # Auto-detect based on fields
            if "_time" in event and "sourcetype" in event:
                alerts.append(from_splunk_event(event))
            elif "@timestamp" in event and "ecs" in event:
                alerts.append(from_elastic_ecs(event))
            elif "systemAlertId" in event:
                alerts.append(from_sentinel_alert(event))
            else:
                alerts.append(from_generic_json(event))

    return alerts


# ── Export: Incident → SIEM ──────────────────────────────────────────────────

def to_splunk_hec(incident: Incident, hec_url: str, hec_token: str) -> dict:
    """Send an incident to Splunk via HEC (HTTP Event Collector)."""
    payload = {
        "time": _iso_to_epoch(incident.created_at),
        "source": "ai_soc",
        "sourcetype": "ai_soc:incident",
        "index": "security",
        "event": {
            "incident_id": incident.id,
            "priority": incident.priority,
            "classification": incident.classification,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "ttps": incident.ttps,
            "iocs": incident.iocs,
            "affected_assets": incident.affected_assets,
            "alert_count": len(incident.alerts),
        },
    }

    try:
        response = requests.post(
            hec_url,
            headers={"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"},
            json=payload,
            timeout=10,
            verify=False,
        )
        return {"success": response.status_code == 200, "status_code": response.status_code, "response": response.text}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)}


def to_elasticsearch(incident: Incident, es_url: str, index: str = "ai-soc-incidents", api_key: str = None) -> dict:
    """Index an incident in Elasticsearch."""
    doc = {
        "@timestamp": incident.created_at,
        "incident_id": incident.id,
        "priority": incident.priority,
        "classification": incident.classification,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "ttps": incident.ttps,
        "iocs": incident.iocs,
        "affected_assets": incident.affected_assets,
        "alert_count": len(incident.alerts),
        "triage_summary": incident.triage_summary,
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    try:
        response = requests.post(
            f"{es_url}/{index}/_doc/{incident.id}",
            headers=headers,
            json=doc,
            timeout=10,
        )
        return {"success": response.status_code in (200, 201), "status_code": response.status_code}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)}


def to_webhook(incident: Incident, webhook_url: str, headers: dict = None) -> dict:
    """Send an incident to a generic webhook endpoint."""
    payload = {
        "incident_id": incident.id,
        "priority": incident.priority,
        "classification": incident.classification,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "ttps": incident.ttps,
        "ioc_count": len(incident.iocs),
        "affected_assets": incident.affected_assets,
        "triage_summary": incident.triage_summary,
        "created_at": incident.created_at,
    }

    try:
        response = requests.post(
            webhook_url,
            headers=headers or {"Content-Type": "application/json"},
            json=payload,
            timeout=10,
        )
        return {"success": response.status_code < 400, "status_code": response.status_code}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)}


def to_ndjson_file(incidents: List[Incident], output_path: str):
    """Write incidents as NDJSON for bulk import into any SIEM."""
    with open(output_path, "w") as f:
        for incident in incidents:
            record = incident.to_dict()
            record["final_report"] = incident.final_report
            f.write(json.dumps(record) + "\n")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _normalize_severity(raw: str) -> str:
    """Normalize various severity strings to critical/high/medium/low."""
    s = str(raw).lower().strip()
    if s in ("critical", "crit", "p1", "1", "emergency", "fatal"):
        return "critical"
    if s in ("high", "h", "p2", "2", "major", "severe", "error"):
        return "high"
    if s in ("medium", "med", "m", "p3", "3", "moderate", "warning", "warn"):
        return "medium"
    return "low"


def _iso_to_epoch(iso_str: str) -> float:
    """Convert ISO timestamp to Unix epoch."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, AttributeError):
        return datetime.utcnow().timestamp()
