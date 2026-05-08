"""
Incident Board — browse, filter, and drill into all processed incidents.
"""

import json
import os
import sys

import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.state import init_state, sidebar_config, PRIORITY_COLORS, SEVERITY_COLORS

st.set_page_config(page_title="Incident Board | AI SOC", page_icon="📋", layout="wide")
init_state()
sidebar_config()

st.title("📋 Incident Board")
st.caption("All detected incidents with full investigation details.")

incidents = st.session_state.incidents

if not incidents:
    st.markdown(
        """
        <div style="text-align:center;padding:4rem;color:#64748b">
            <div style="font-size:4rem">📭</div>
            <h3>No incidents yet</h3>
            <p>Process alerts in <strong>Live SOC</strong> or <strong>Alert Queue</strong> first.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# ── Filters ───────────────────────────────────────────────────────────────────
with st.expander("🔎 Filters", expanded=False):
    fc1, fc2, fc3, fc4 = st.columns(4)
    filter_priority = fc1.multiselect("Priority", ["P1", "P2", "P3", "P4"])
    filter_status = fc2.multiselect("Status", ["open", "investigating", "contained", "resolved"])
    all_types = sorted({i.classification for i in incidents})
    filter_type = fc3.multiselect("Classification", all_types)
    filter_risk = fc4.slider("Min Risk Score", 0.0, 10.0, 0.0, 0.5)

filtered = incidents
if filter_priority:
    filtered = [i for i in filtered if i.priority in filter_priority]
if filter_status:
    filtered = [i for i in filtered if i.status in filter_status]
if filter_type:
    filtered = [i for i in filtered if i.classification in filter_type]
if filter_risk > 0:
    filtered = [i for i in filtered if i.risk_score >= filter_risk]

st.caption(f"Showing {len(filtered)} of {len(incidents)} incidents")

# ── Incident cards ────────────────────────────────────────────────────────────
for incident in filtered:
    p_color = PRIORITY_COLORS.get(incident.priority, "#94a3b8")
    risk_color = "#EF4444" if incident.risk_score >= 7 else "#F97316" if incident.risk_score >= 4 else "#22C55E"
    status_icon = {"open": "🚨", "investigating": "🔍", "contained": "🔒", "resolved": "✅"}.get(incident.status, "❓")

    with st.expander(
        f"{status_icon} **{incident.id}** — {incident.classification.replace('_',' ').title()} "
        f"| {incident.priority} | Risk {incident.risk_score}/10 | {incident.created_at[:10]}",
        expanded=False,
    ):
        # Header bar
        st.markdown(
            f"""
            <div style="background:#1e293b;border-radius:8px;padding:1rem;
                        border-left:4px solid {p_color};margin-bottom:1rem">
                <div style="display:flex;gap:2rem;flex-wrap:wrap;color:#f8fafc">
                    <span>🎯 Priority: <strong style="color:{p_color}">{incident.priority}</strong></span>
                    <span>⚠️ Risk: <strong style="color:{risk_color}">{incident.risk_score}/10</strong></span>
                    <span>📌 Status: <strong>{incident.status.title()}</strong></span>
                    <span>🕐 Created: <strong>{incident.created_at[:19].replace("T"," ")}</strong></span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Columns: TTPs / IOCs / Assets / Alert info
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown("**🎯 MITRE TTPs**")
            if incident.ttps:
                for ttp in incident.ttps[:6]:
                    st.markdown(f"- `{ttp}`")
                if len(incident.ttps) > 6:
                    st.caption(f"+{len(incident.ttps)-6} more")
            else:
                st.caption("None")

        with col2:
            st.markdown("**🔍 IOCs**")
            if incident.iocs:
                for ioc in incident.iocs[:6]:
                    st.markdown(f"- `{ioc}`")
                if len(incident.iocs) > 6:
                    st.caption(f"+{len(incident.iocs)-6} more")
            else:
                st.caption("None")

        with col3:
            st.markdown("**🖥️ Affected Assets**")
            if incident.affected_assets:
                for asset in incident.affected_assets[:5]:
                    st.markdown(f"- `{asset}`")
            else:
                st.caption("Unknown")

        with col4:
            st.markdown("**🚨 Source Alert**")
            if incident.alerts:
                a = incident.alerts[0]
                sev_color = SEVERITY_COLORS.get(a.severity, "#94a3b8")
                st.markdown(f"ID: `{a.id}`")
                st.markdown(f"Type: `{a.alert_type}`")
                st.markdown(
                    f"Severity: <span style='color:{sev_color}'><b>{a.severity.upper()}</b></span>",
                    unsafe_allow_html=True,
                )
                if a.source_ip:
                    st.markdown(f"Src IP: `{a.source_ip}`")

        # Risk gauge
        gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=incident.risk_score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Risk Score", "font": {"color": "#94a3b8"}},
            gauge={
                "axis": {"range": [0, 10], "tickcolor": "#475569"},
                "bar": {"color": risk_color},
                "bgcolor": "#1e293b",
                "steps": [
                    {"range": [0, 4], "color": "#064e3b"},
                    {"range": [4, 7], "color": "#78350f"},
                    {"range": [7, 10], "color": "#7f1d1d"},
                ],
            },
        ))
        gauge.update_layout(
            height=200, margin=dict(t=30, b=10, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
        )
        st.plotly_chart(gauge, use_container_width=True)

        # Triage summary
        if incident.triage_summary:
            with st.container(border=True):
                st.markdown("**🎯 Triage Assessment**")
                st.markdown(incident.triage_summary[:600] + ("…" if len(incident.triage_summary) > 600 else ""))

        # Tabs for detailed views
        tab_intel, tab_log, tab_play, tab_report = st.tabs(
            ["🔬 Threat Intel", "📋 Log Analysis", "🛡️ Playbook", "📝 Report"]
        )

        with tab_intel:
            if incident.threat_intel_summary:
                st.markdown(incident.threat_intel_summary)
            else:
                st.caption("No threat intel data")

        with tab_log:
            if incident.log_analysis_summary:
                st.markdown(incident.log_analysis_summary)
            else:
                st.caption("No log analysis data")

        with tab_play:
            if incident.playbook:
                st.markdown(incident.playbook)
            else:
                st.caption("No playbook generated")

        with tab_report:
            if incident.final_report:
                st.markdown(incident.final_report)
            else:
                st.caption("No report generated")

        # Export
        st.download_button(
            "⬇️ Export Incident JSON",
            data=json.dumps(
                {
                    **incident.to_dict(),
                    "final_report": incident.final_report,
                    "executive_summary": incident.executive_summary,
                    "playbook": incident.playbook,
                },
                indent=2,
            ),
            file_name=f"{incident.id}.json",
            mime="application/json",
            key=f"export_{incident.id}",
        )
