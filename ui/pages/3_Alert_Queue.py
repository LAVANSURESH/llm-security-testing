"""
Alert Queue — load, preview, and batch-process alerts from files or paste.
Supports JSON, NDJSON, Splunk, Elastic/ECS, Sentinel, and CEF formats.
"""

import json
import os
import sys
import io

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.state import init_state, sidebar_config, add_incident, SEVERITY_COLORS
from soc.models.alert import Alert

st.set_page_config(page_title="Alert Queue | AI SOC", page_icon="📥", layout="wide")
init_state()
sidebar_config()

st.title("📥 Alert Queue")
st.caption("Load alerts from files or paste raw events. Preview them before sending to the SOC agents.")

SAMPLE_ALERTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "soc", "data", "sample_alerts.json"
)
SAMPLE_LOGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "soc", "data", "sample_logs.json"
)

# ── Source selection ──────────────────────────────────────────────────────────
src_tab1, src_tab2, src_tab3, src_tab4 = st.tabs([
    "🔖 Sample Data", "📁 Upload File", "📋 Paste JSON/CEF", "🔌 SIEM Formats"
])

raw_alerts: list[dict] = []

with src_tab1:
    st.markdown("Load the built-in sample alerts (10 realistic scenarios).")
    col1, col2 = st.columns([2, 1])
    with col1:
        with open(SAMPLE_ALERTS_PATH) as f:
            samples = json.load(f)
        preview_df = pd.DataFrame([{
            "ID": s.get("id"),
            "Type": s.get("alert_type", "").replace("_", " ").title(),
            "Severity": s.get("severity", "").upper(),
            "Source": s.get("source"),
            "Description": s.get("description", "")[:60] + "…",
        } for s in samples])
        st.dataframe(preview_df, use_container_width=True, hide_index=True)
    with col2:
        limit = st.number_input("Max alerts to load", 1, 10, 10)
        if st.button("📥 Load Sample Alerts", use_container_width=True, type="primary"):
            st.session_state["alert_queue"] = samples[:limit]
            st.success(f"Loaded {min(limit, len(samples))} sample alerts into queue")

with src_tab2:
    uploaded = st.file_uploader(
        "Upload alert file (JSON array or NDJSON)",
        type=["json", "ndjson", "txt"],
    )
    fmt = st.selectbox("SIEM Format", ["auto", "splunk", "elastic", "sentinel"], key="upload_fmt")
    if uploaded and st.button("Load File", type="primary"):
        content = uploaded.read().decode("utf-8").strip()
        try:
            if content.startswith("["):
                events = json.loads(content)
            else:
                events = [json.loads(line) for line in content.splitlines() if line.strip()]

            if fmt == "auto":
                st.session_state["alert_queue"] = events
                st.success(f"Loaded {len(events)} alerts (generic JSON format)")
            else:
                from soc.tools.siem_integration import (
                    from_splunk_event, from_elastic_ecs, from_sentinel_alert
                )
                converters = {
                    "splunk": from_splunk_event,
                    "elastic": from_elastic_ecs,
                    "sentinel": from_sentinel_alert,
                }
                converted = [converters[fmt](e).to_dict() for e in events]
                st.session_state["alert_queue"] = converted
                st.success(f"Loaded {len(converted)} alerts from {fmt} format")
        except Exception as e:
            st.error(f"Parse error: {e}")

with src_tab3:
    pasted = st.text_area(
        "Paste JSON array, NDJSON, or a single alert",
        height=200,
        placeholder='[{"source":"firewall","alert_type":"brute_force","severity":"high",...}]'
    )
    cef_input = st.text_area(
        "Or paste CEF syslog lines (one per line)",
        height=100,
        placeholder="CEF:0|Palo Alto|Firewall|9.0|100|Brute Force|8|src=1.2.3.4 dst=10.0.0.1"
    )
    if st.button("Parse Input", type="primary"):
        parsed = []
        errors = []
        if pasted.strip():
            try:
                data = json.loads(pasted)
                if isinstance(data, list):
                    parsed.extend(data)
                else:
                    parsed.append(data)
            except json.JSONDecodeError:
                try:
                    for line in pasted.strip().splitlines():
                        if line.strip():
                            parsed.append(json.loads(line))
                except Exception as e:
                    errors.append(f"JSON parse error: {e}")

        if cef_input.strip():
            from soc.tools.siem_integration import from_cef_syslog
            for line in cef_input.strip().splitlines():
                if line.strip():
                    try:
                        parsed.append(from_cef_syslog(line).to_dict())
                    except Exception as e:
                        errors.append(f"CEF parse error: {e}")

        if errors:
            for err in errors:
                st.warning(err)
        if parsed:
            st.session_state["alert_queue"] = parsed
            st.success(f"Parsed {len(parsed)} alert(s)")

with src_tab4:
    st.markdown("""
    ### Supported SIEM Ingestion Formats

    | Format | Description | Key Fields Used |
    |--------|-------------|-----------------|
    | **Splunk** | JSON search results | `_time`, `signature`, `src_ip`, `severity` |
    | **Elastic/ECS** | Elastic Common Schema | `@timestamp`, `event.category`, `source.ip` |
    | **Microsoft Sentinel** | Azure Monitor alerts | `systemAlertId`, `entities[].kind` |
    | **CEF Syslog** | Common Event Format | Standard CEF key-value extensions |
    | **Generic JSON** | Any flat key-value JSON | Auto-maps common field names |

    ### Export Formats for SIEM Push

    Processed incidents can be exported to:
    - **Splunk HEC** — HTTP Event Collector endpoint
    - **Elasticsearch** — Direct index push
    - **Webhook** — Any REST endpoint
    - **NDJSON** — Bulk file export
    """)

# ── Alert Queue viewer ────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("📋 Queue")

queue = st.session_state.get("alert_queue", [])

if not queue:
    st.info("Queue is empty. Load alerts from one of the sources above.")
else:
    st.caption(f"{len(queue)} alert(s) in queue")

    # Preview table
    preview_rows = []
    for i, a in enumerate(queue):
        sev = a.get("severity", "unknown")
        preview_rows.append({
            "#": i + 1,
            "ID": a.get("id", f"alert-{i}"),
            "Type": a.get("alert_type", "unknown").replace("_", " ").title(),
            "Severity": sev.upper(),
            "Source": a.get("source", "—"),
            "Src IP": a.get("source_ip", "—"),
            "User": a.get("user", "—"),
            "Description": str(a.get("description", ""))[:60] + "…",
        })
    st.dataframe(pd.DataFrame(preview_rows), use_container_width=True, hide_index=True)

    st.markdown("---")
    c1, c2, c3 = st.columns([1, 1, 2])
    process_limit = c1.number_input("Process at most", 1, len(queue), min(len(queue), 3))
    with c2:
        include_logs = st.checkbox("Include sample logs", value=True)
        clear_btn = st.button("🗑️ Clear Queue")
        if clear_btn:
            st.session_state["alert_queue"] = []
            st.rerun()

    process_btn = c3.button(
        f"🚀 Process {process_limit} Alert(s) with SOC Agents",
        type="primary",
        use_container_width=True,
    )

    if process_btn:
        api_key = st.session_state.get("api_key", "")
        if not api_key:
            st.error("No API key configured. Go to ⚙️ Settings.")
            st.stop()

        log_entries = []
        if include_logs and os.path.exists(SAMPLE_LOGS_PATH):
            with open(SAMPLE_LOGS_PATH) as f:
                log_entries = json.load(f)

        from soc.orchestrator.soc_orchestrator import SOCOrchestrator

        orchestrator = SOCOrchestrator(
            model=st.session_state.get("model"),
            api_key=api_key,
            provider=st.session_state.get("provider", "anthropic"),
        )

        to_process = queue[:process_limit]
        progress_bar = st.progress(0, text="Starting…")
        results_placeholder = st.empty()
        new_incidents = []
        false_positives = 0

        for idx, alert_data in enumerate(to_process):
            progress_bar.progress(
                (idx) / len(to_process),
                text=f"Processing alert {idx+1}/{len(to_process)}: {alert_data.get('alert_type','?')}",
            )

            try:
                alert_obj = Alert.from_dict(alert_data)
            except Exception as e:
                st.warning(f"Skipping malformed alert {idx+1}: {e}")
                continue

            with st.status(
                f"Agent workflow: {alert_obj.alert_type} ({alert_obj.severity})",
                expanded=False,
            ) as s:
                agent_lines: list[str] = []
                placeholder = st.empty()

                def cb(agent_name, msg, _placeholder=placeholder, _lines=agent_lines):
                    icons = {
                        "TriageAgent": "🎯", "ThreatIntelAgent": "🔬",
                        "LogAnalysisAgent": "📋", "IRAgent": "🛡️",
                        "ReportingAgent": "📝", "Orchestrator": "⚙️",
                    }
                    _lines.append(f"{icons.get(agent_name, '🤖')} **{agent_name}**: {msg}")
                    _placeholder.markdown("\n\n".join(_lines[-8:]))

                incident = orchestrator.process_alert(alert_obj, log_entries, cb)

            if incident:
                add_incident(incident)
                new_incidents.append(incident)
                s.update(label=f"✅ {incident.id} — Risk {incident.risk_score}/10", state="complete")
            else:
                false_positives += 1
                s.update(label=f"⚪ False positive dismissed", state="complete")

        progress_bar.progress(1.0, text="All done!")

        # Summary
        st.success(
            f"Processed {len(to_process)} alert(s): "
            f"**{len(new_incidents)} incident(s)** created, "
            f"**{false_positives}** false positive(s) dismissed."
        )

        if new_incidents:
            st.markdown("**Created incidents:**")
            for inc in new_incidents:
                p_color = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(inc.priority, "⚪")
                st.markdown(
                    f"- {p_color} **{inc.id}** — {inc.classification.replace('_',' ').title()} "
                    f"| Risk {inc.risk_score}/10"
                )

        # Remove processed alerts from queue
        st.session_state["alert_queue"] = queue[process_limit:]

# ── SIEM Push ─────────────────────────────────────────────────────────────────
incidents = st.session_state.incidents
if incidents:
    st.markdown("---")
    st.subheader("📤 Export / Push to SIEM")

    ex_tab1, ex_tab2, ex_tab3, ex_tab4 = st.tabs(
        ["NDJSON File", "Splunk HEC", "Elasticsearch", "Webhook"]
    )

    with ex_tab1:
        st.markdown("Download all incidents as NDJSON for bulk import.")
        ndjson_lines = []
        for inc in incidents:
            record = inc.to_dict()
            record["final_report"] = inc.final_report
            ndjson_lines.append(json.dumps(record))
        ndjson_data = "\n".join(ndjson_lines)
        st.download_button(
            "⬇️ Download incidents.ndjson",
            data=ndjson_data,
            file_name="incidents.ndjson",
            mime="application/x-ndjson",
        )

    with ex_tab2:
        hec_url = st.text_input("Splunk HEC URL", placeholder="https://splunk.company.com:8088/services/collector")
        hec_token = st.text_input("HEC Token", type="password")
        if st.button("Push to Splunk") and hec_url and hec_token:
            from soc.tools.siem_integration import to_splunk_hec
            results = [to_splunk_hec(inc, hec_url, hec_token) for inc in incidents]
            ok = sum(1 for r in results if r.get("success"))
            st.success(f"Sent {ok}/{len(incidents)} incidents to Splunk HEC")

    with ex_tab3:
        es_url = st.text_input("Elasticsearch URL", placeholder="https://elastic.company.com:9200")
        es_key = st.text_input("API Key", type="password")
        es_index = st.text_input("Index", value="ai-soc-incidents")
        if st.button("Push to Elasticsearch") and es_url:
            from soc.tools.siem_integration import to_elasticsearch
            results = [to_elasticsearch(inc, es_url, es_index, es_key or None) for inc in incidents]
            ok = sum(1 for r in results if r.get("success"))
            st.success(f"Indexed {ok}/{len(incidents)} incidents")

    with ex_tab4:
        wh_url = st.text_input("Webhook URL", placeholder="https://hooks.example.com/soc-incident")
        if st.button("Send to Webhook") and wh_url:
            from soc.tools.siem_integration import to_webhook
            results = [to_webhook(inc, wh_url) for inc in incidents]
            ok = sum(1 for r in results if r.get("success"))
            st.success(f"Sent {ok}/{len(incidents)} incidents to webhook")
