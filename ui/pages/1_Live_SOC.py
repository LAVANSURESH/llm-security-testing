"""
Live SOC — process a single alert through all AI agents in real time.
Watch each agent's reasoning stream into the UI step by step.
"""

import json
import os
import sys
import time

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.state import init_state, sidebar_config, add_incident, PRIORITY_COLORS, SEVERITY_COLORS
from soc.models.alert import Alert

st.set_page_config(page_title="Live SOC | AI SOC", page_icon="⚡", layout="wide")
init_state()
sidebar_config()

st.title("⚡ Live SOC — Real-Time Agent Processing")
st.caption(
    "Submit a security alert and watch the AI agents triage, investigate, "
    "and respond autonomously."
)

# ── Alert input tabs ──────────────────────────────────────────────────────────
tab_sample, tab_json, tab_form = st.tabs(["📋 Sample Alerts", "📄 Paste JSON", "✍️ Build Alert"])

selected_alert_data: dict | None = None

with tab_sample:
    sample_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "soc", "data", "sample_alerts.json"
    )
    with open(sample_file) as f:
        samples = json.load(f)

    ICONS = {
        "brute_force": "🔨", "ransomware": "💀", "lateral_movement": "↔️",
        "data_exfiltration": "📤", "privilege_escalation": "⬆️", "sql_injection": "💉",
        "phishing": "🎣", "anomalous_login": "👤", "reconnaissance": "🔍", "prompt_injection": "🤖",
    }
    cols = st.columns(2)
    for i, s in enumerate(samples):
        icon = ICONS.get(s["alert_type"], "🚨")
        sev_color = SEVERITY_COLORS.get(s["severity"], "#94a3b8")
        with cols[i % 2]:
            with st.container(border=True):
                st.markdown(
                    f"**{icon} {s['alert_type'].replace('_',' ').title()}** &nbsp; "
                    f"<span style='color:{sev_color};font-weight:bold'>{s['severity'].upper()}</span>",
                    unsafe_allow_html=True,
                )
                st.caption(s["description"][:100] + "…")
                if st.button("Select", key=f"sample_{i}", use_container_width=True):
                    st.session_state["pending_alert"] = s

    if st.session_state.get("pending_alert") and st.session_state["pending_alert"] in samples:
        st.success(f"Selected: {st.session_state['pending_alert']['alert_type']}")
        selected_alert_data = st.session_state["pending_alert"]

with tab_json:
    placeholder_json = json.dumps({
        "source": "firewall",
        "alert_type": "brute_force",
        "severity": "high",
        "description": "550 failed SSH logins from 185.220.101.50",
        "source_ip": "185.220.101.50",
        "dest_ip": "10.0.1.15",
        "user": "admin",
        "hostname": "web-server-01",
        "raw_data": {"failure_count": 550},
    }, indent=2)
    json_input = st.text_area("Paste alert JSON", value="", height=250, placeholder=placeholder_json)
    if json_input.strip():
        try:
            selected_alert_data = json.loads(json_input)
            st.success("JSON parsed successfully")
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}")

with tab_form:
    with st.form("build_alert"):
        f1, f2 = st.columns(2)
        source = f1.selectbox("Source", ["firewall", "endpoint", "siem", "web_proxy", "email_gateway", "network_ids", "llm_security"])
        severity = f2.selectbox("Severity", ["critical", "high", "medium", "low"])
        alert_type = st.selectbox("Alert Type", [
            "brute_force", "ransomware", "lateral_movement", "data_exfiltration",
            "privilege_escalation", "sql_injection", "phishing", "anomalous_login",
            "reconnaissance", "prompt_injection", "malware",
        ])
        description = st.text_area("Description", height=80, placeholder="Describe the security event…")
        f3, f4 = st.columns(2)
        source_ip = f3.text_input("Source IP", placeholder="185.220.101.50")
        dest_ip = f4.text_input("Dest IP", placeholder="10.0.1.15")
        f5, f6 = st.columns(2)
        user = f5.text_input("User", placeholder="admin")
        hostname = f6.text_input("Hostname", placeholder="web-server-01")

        if st.form_submit_button("Build Alert", use_container_width=True):
            selected_alert_data = {
                "source": source, "alert_type": alert_type, "severity": severity,
                "description": description or f"{alert_type} detected",
                "source_ip": source_ip or None, "dest_ip": dest_ip or None,
                "user": user or None, "hostname": hostname or None,
                "raw_data": {},
            }
            st.session_state["pending_alert"] = selected_alert_data

# Persist across reruns
if st.session_state.get("pending_alert") and selected_alert_data is None:
    selected_alert_data = st.session_state.get("pending_alert")

# ── Process panel ─────────────────────────────────────────────────────────────
st.markdown("---")

if selected_alert_data:
    alert_obj = Alert.from_dict(selected_alert_data)

    sev_color = SEVERITY_COLORS.get(alert_obj.severity, "#94a3b8")
    st.markdown(
        f"**Selected alert:** `{alert_obj.id}` &nbsp;|&nbsp; "
        f"**{alert_obj.alert_type.replace('_',' ').title()}** &nbsp;|&nbsp; "
        f"<span style='color:{sev_color}'><b>{alert_obj.severity.upper()}</b></span>",
        unsafe_allow_html=True,
    )

    col_btn, col_logs = st.columns([1, 3])
    with col_btn:
        load_logs = st.checkbox("Include sample logs", value=True)
        run = st.button("🚀 Run SOC Agents", type="primary", use_container_width=True)

    if run:
        api_key = st.session_state.get("api_key", "")
        if not api_key:
            st.error("No API key configured. Go to ⚙️ Settings to add one.")
            st.stop()

        # Load logs
        log_entries = []
        if load_logs:
            log_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "soc", "data", "sample_logs.json"
            )
            if os.path.exists(log_file):
                with open(log_file) as f:
                    log_entries = json.load(f)

        from soc.orchestrator.soc_orchestrator import SOCOrchestrator

        orchestrator = SOCOrchestrator(
            model=st.session_state.get("model"),
            api_key=api_key,
            provider=st.session_state.get("provider", "anthropic"),
        )

        # ── Step-by-step agent status display ────────────────────────────────
        agent_log: list[str] = []

        with st.status("🤖 AI Agents Running…", expanded=True) as status_box:
            agent_placeholder = st.empty()

            def update_status(agent_name: str, msg: str):
                icons = {
                    "TriageAgent": "🎯", "ThreatIntelAgent": "🔬",
                    "LogAnalysisAgent": "📋", "IRAgent": "🛡️",
                    "ReportingAgent": "📝", "Orchestrator": "⚙️",
                }
                icon = icons.get(agent_name, "🤖")
                agent_log.append(f"{icon} **{agent_name}**: {msg}")
                agent_placeholder.markdown("\n\n".join(agent_log[-12:]))

            incident = orchestrator.process_alert(alert_obj, log_entries, update_status)

        if incident is None:
            status_box.update(label="✅ Alert dismissed as false positive", state="complete")
            st.warning(f"Alert `{alert_obj.id}` was classified as a **false positive** by the Triage Agent.")
        else:
            status_box.update(label=f"✅ Incident {incident.id} created", state="complete")
            add_incident(incident)
            st.session_state["pending_alert"] = None

            # ── Results display ───────────────────────────────────────────────
            p_color = PRIORITY_COLORS.get(incident.priority, "#94a3b8")
            risk_color = "#EF4444" if incident.risk_score >= 7 else "#F97316" if incident.risk_score >= 4 else "#22C55E"

            st.markdown(
                f"""
                <div style="background:#1e293b;border-radius:10px;padding:1.5rem;
                            border-left:4px solid {p_color};margin-top:1rem">
                    <h3 style="color:#f8fafc;margin:0">Incident {incident.id}</h3>
                    <div style="display:flex;gap:2rem;margin-top:0.8rem;flex-wrap:wrap">
                        <span>Priority: <strong style="color:{p_color}">{incident.priority}</strong></span>
                        <span>Risk: <strong style="color:{risk_color}">{incident.risk_score}/10</strong></span>
                        <span>Classification: <strong>{incident.classification.replace('_',' ').title()}</strong></span>
                        <span>Status: <strong>{incident.status.title()}</strong></span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            res1, res2 = st.columns(2)
            with res1:
                st.markdown("**MITRE ATT&CK TTPs**")
                if incident.ttps:
                    for ttp in incident.ttps:
                        st.markdown(f"- `{ttp}`")
                else:
                    st.caption("None identified")

                st.markdown("**Affected Assets**")
                for asset in incident.affected_assets or ["Unknown"]:
                    st.markdown(f"- `{asset}`")

            with res2:
                st.markdown("**Indicators of Compromise**")
                if incident.iocs:
                    for ioc in incident.iocs[:10]:
                        st.markdown(f"- `{ioc}`")
                    if len(incident.iocs) > 10:
                        st.caption(f"+{len(incident.iocs)-10} more")
                else:
                    st.caption("None extracted")

            with st.expander("📋 Response Playbook", expanded=False):
                if incident.playbook:
                    st.markdown(incident.playbook)

            with st.expander("📝 Full Incident Report", expanded=False):
                if incident.final_report:
                    st.markdown(incident.final_report)

            with st.expander("📊 Executive Summary", expanded=False):
                if incident.executive_summary:
                    st.markdown(incident.executive_summary)

            st.success(f"Incident **{incident.id}** saved. View details in 📋 Incident Board.")
else:
    st.info("Select or build an alert above to begin.")
