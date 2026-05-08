"""
Reports — view, search, and export incident reports and executive summaries.
"""

import json
import os
import sys

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.state import init_state, sidebar_config, PRIORITY_COLORS

st.set_page_config(page_title="Reports | AI SOC", page_icon="📝", layout="wide")
init_state()
sidebar_config()

st.title("📝 SOC Reports")
st.caption("Browse incident reports, executive summaries, and analytics.")

incidents = st.session_state.incidents

if not incidents:
    st.info("No incidents yet. Process alerts to generate reports.")
    st.stop()

# ── Analytics overview ────────────────────────────────────────────────────────
st.subheader("📊 SOC Analytics")

met1, met2, met3, met4 = st.columns(4)
total = len(incidents)
avg_risk = round(sum(i.risk_score for i in incidents) / total, 1) if total else 0
total_ttps = sum(len(i.ttps) for i in incidents)
total_iocs = sum(len(i.iocs) for i in incidents)

met1.metric("Total Incidents", total)
met2.metric("Average Risk Score", f"{avg_risk}/10")
met3.metric("Total TTPs Detected", total_ttps)
met4.metric("Total IOCs", total_iocs)

# Charts
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("**Incidents by Classification**")
    class_counts: dict = {}
    for inc in incidents:
        label = inc.classification.replace("_", " ").title()
        class_counts[label] = class_counts.get(label, 0) + 1
    if class_counts:
        fig = px.pie(
            names=list(class_counts.keys()),
            values=list(class_counts.values()),
            hole=0.4,
            color_discrete_sequence=px.colors.sequential.Reds_r,
        )
        fig.update_layout(
            height=280, margin=dict(t=10, b=10), showlegend=True,
            paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
        )
        st.plotly_chart(fig, use_container_width=True)

with chart_col2:
    st.markdown("**Risk Scores Over Time**")
    risk_df = pd.DataFrame([{
        "Incident": inc.id,
        "Risk": inc.risk_score,
        "Priority": inc.priority,
        "Created": inc.created_at[:10],
    } for inc in incidents])
    fig = px.scatter(
        risk_df, x="Created", y="Risk", color="Priority",
        size="Risk", hover_data=["Incident"],
        color_discrete_map={"P1": "#EF4444", "P2": "#F97316", "P3": "#EAB308", "P4": "#22C55E"},
    )
    fig.update_layout(
        height=280, margin=dict(t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
        yaxis=dict(range=[0, 10.5]),
    )
    st.plotly_chart(fig, use_container_width=True)

# MITRE frequency heatmap
st.markdown("**MITRE ATT&CK TTP Frequency**")
ttp_counter: dict = {}
for inc in incidents:
    for ttp in inc.ttps:
        ttp_counter[ttp] = ttp_counter.get(ttp, 0) + 1

if ttp_counter:
    sorted_ttps = sorted(ttp_counter.items(), key=lambda x: x[1], reverse=True)[:15]
    ttp_df = pd.DataFrame(sorted_ttps, columns=["TTP", "Count"])

    # Load MITRE names if available
    mitre_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "soc", "data", "mitre_patterns.json"
    )
    ttp_names = {}
    if os.path.exists(mitre_file):
        with open(mitre_file) as f:
            mitre_data = json.load(f)
        ttp_names = {k: v.get("name", k) for k, v in mitre_data.get("techniques", {}).items()}

    ttp_df["Name"] = ttp_df["TTP"].map(lambda t: ttp_names.get(t, t))
    ttp_df["Label"] = ttp_df["TTP"] + " — " + ttp_df["Name"]

    fig = px.bar(
        ttp_df, x="Count", y="Label", orientation="h",
        color="Count", color_continuous_scale="Reds",
    )
    fig.update_layout(
        height=max(200, len(sorted_ttps) * 28),
        margin=dict(t=10, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0", yaxis=dict(autorange="reversed"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ── Report browser ────────────────────────────────────────────────────────────
st.subheader("📄 Incident Reports")

# Search
search = st.text_input("🔍 Search incidents", placeholder="incident ID, classification, TTP…")
if search:
    s = search.lower()
    incidents = [
        i for i in incidents
        if s in i.id.lower()
        or s in i.classification.lower()
        or any(s in t.lower() for t in i.ttps)
        or any(s in ioc.lower() for ioc in i.iocs)
    ]
    st.caption(f'{len(incidents)} match(es) for "{search}"')

# Incident selector
if not incidents:
    st.warning("No incidents match your search.")
    st.stop()

inc_options = {
    f"{inc.id} — {inc.classification.replace('_',' ').title()} ({inc.priority}, Risk {inc.risk_score}/10)": inc
    for inc in incidents
}
selected_label = st.selectbox("Select Incident", list(inc_options.keys()))
selected = inc_options[selected_label]

# Report tabs
rtab1, rtab2, rtab3, rtab4 = st.tabs([
    "📝 Full Technical Report", "📊 Executive Summary", "🛡️ Response Playbook", "📋 Raw Incident Data"
])

with rtab1:
    if selected.final_report:
        st.markdown(selected.final_report)
        st.download_button(
            "⬇️ Download Report (Markdown)",
            data=selected.final_report,
            file_name=f"{selected.id}_report.md",
            mime="text/markdown",
        )
    else:
        st.info("No technical report available for this incident.")

with rtab2:
    if selected.executive_summary:
        st.markdown(selected.executive_summary)
        st.download_button(
            "⬇️ Download Executive Summary",
            data=selected.executive_summary,
            file_name=f"{selected.id}_executive_summary.md",
            mime="text/markdown",
        )
    else:
        st.info("No executive summary available.")

with rtab3:
    if selected.playbook:
        st.markdown(selected.playbook)
        st.download_button(
            "⬇️ Download Playbook",
            data=selected.playbook,
            file_name=f"{selected.id}_playbook.md",
            mime="text/markdown",
        )
    else:
        st.info("No playbook available.")

with rtab4:
    incident_dict = selected.to_dict()
    st.json(incident_dict)
    st.download_button(
        "⬇️ Download Incident JSON",
        data=json.dumps(
            {**incident_dict, "final_report": selected.final_report,
             "executive_summary": selected.executive_summary, "playbook": selected.playbook},
            indent=2
        ),
        file_name=f"{selected.id}.json",
        mime="application/json",
    )

# ── Bulk export ───────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("📦 Bulk Export")

all_incidents = st.session_state.incidents
bc1, bc2 = st.columns(2)

with bc1:
    all_json = json.dumps([
        {
            **i.to_dict(),
            "final_report": i.final_report,
            "executive_summary": i.executive_summary,
            "playbook": i.playbook,
        }
        for i in all_incidents
    ], indent=2)
    st.download_button(
        f"⬇️ All {len(all_incidents)} Incidents (JSON)",
        data=all_json,
        file_name="all_incidents.json",
        mime="application/json",
        use_container_width=True,
    )

with bc2:
    summary_rows = [
        f"# {i.id}\n"
        f"**Priority:** {i.priority} | **Risk:** {i.risk_score}/10 | **Status:** {i.status}\n\n"
        f"{i.executive_summary or i.triage_summary or 'No summary'}\n\n---\n"
        for i in all_incidents
    ]
    st.download_button(
        f"⬇️ All Executive Summaries (Markdown)",
        data="\n".join(summary_rows),
        file_name="executive_summaries.md",
        mime="text/markdown",
        use_container_width=True,
    )
