"""
AI-Powered Cybersecurity SOC — Streamlit Web UI
Main dashboard page.
"""

import os
import sys
import json

import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.state import init_state, sidebar_config, compute_metrics, PRIORITY_COLORS, SEVERITY_COLORS

st.set_page_config(
    page_title="AI SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_state()
sidebar_config()

# ── Header ────────────────────────────────────────────────────────────────────
provider_label = {
    "gemini": "Google Gemini",
    "anthropic": "Anthropic Claude",
    "openai": "OpenAI GPT",
}.get(st.session_state.get("provider", "anthropic"), "Unknown")

st.markdown(
    f"""
    <div style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                padding: 2rem 2.5rem; border-radius: 12px; margin-bottom: 1.5rem;
                border: 1px solid #334155;">
        <h1 style="color: #38bdf8; margin: 0; font-size: 2rem;">
            🛡️ AI-Powered Security Operations Center
        </h1>
        <p style="color: #94a3b8; margin: 0.4rem 0 0; font-size: 1rem;">
            Autonomous SOC Agents &nbsp;·&nbsp; Provider: <strong style="color:#f8fafc">{provider_label}</strong>
            &nbsp;·&nbsp; Model: <strong style="color:#f8fafc">{st.session_state.get("model","—")}</strong>
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── KPI Metrics Row ───────────────────────────────────────────────────────────
metrics = compute_metrics()
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Incidents", metrics["total"])
c2.metric("🔴 P1 Critical", metrics["p1"], delta=None)
c3.metric("🟠 P2 High", metrics["p2"])
c4.metric("⚠️ Open / Investigating", metrics["open"])
c5.metric("Risk Score (avg)", f"{metrics['avg_risk']}/10")

st.markdown("---")

# ── Charts Row ────────────────────────────────────────────────────────────────
incidents = st.session_state.incidents
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("Incidents by Priority")
    if incidents:
        priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for inc in incidents:
            priority_counts[inc.priority] = priority_counts.get(inc.priority, 0) + 1
        fig = go.Figure(go.Pie(
            labels=list(priority_counts.keys()),
            values=list(priority_counts.values()),
            marker_colors=[PRIORITY_COLORS[p] for p in priority_counts],
            hole=0.5,
            textinfo="label+value",
        ))
        fig.update_layout(
            showlegend=False,
            height=280,
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No incidents yet. Process alerts to see data.")

with col_right:
    st.subheader("Risk Score Distribution")
    if incidents:
        risk_scores = [inc.risk_score for inc in incidents]
        labels = [inc.id for inc in incidents]
        colors = [
            "#EF4444" if r >= 7 else "#F97316" if r >= 4 else "#22C55E"
            for r in risk_scores
        ]
        fig = go.Figure(go.Bar(
            x=labels,
            y=risk_scores,
            marker_color=colors,
            text=[f"{r}/10" for r in risk_scores],
            textposition="outside",
        ))
        fig.update_layout(
            yaxis=dict(range=[0, 10.5], title="Risk Score"),
            height=280,
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            xaxis=dict(tickangle=-30),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No risk data yet.")

st.markdown("---")

# ── Recent Incidents Table ────────────────────────────────────────────────────
st.subheader("Recent Incidents")

if incidents:
    rows = []
    for inc in incidents[:20]:
        p_emoji = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}.get(inc.priority, "⚪")
        s_emoji = {"contained": "🔒", "investigating": "🔍", "open": "🚨", "resolved": "✅"}.get(inc.status, "❓")
        rows.append({
            "ID": inc.id,
            "Priority": f"{p_emoji} {inc.priority}",
            "Classification": inc.classification.replace("_", " ").title(),
            "Risk": f"{inc.risk_score}/10",
            "TTPs": len(inc.ttps),
            "IOCs": len(inc.iocs),
            "Assets": len(inc.affected_assets),
            "Status": f"{s_emoji} {inc.status.title()}",
            "Created": inc.created_at[:19].replace("T", " "),
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # MITRE TTP frequency
    st.subheader("Top MITRE ATT&CK Techniques")
    ttp_counter: dict = {}
    for inc in incidents:
        for ttp in inc.ttps:
            ttp_counter[ttp] = ttp_counter.get(ttp, 0) + 1

    if ttp_counter:
        sorted_ttps = sorted(ttp_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        ttp_df = pd.DataFrame(sorted_ttps, columns=["TTP", "Count"])
        fig = px.bar(
            ttp_df, x="Count", y="TTP", orientation="h",
            color="Count", color_continuous_scale="Reds",
        )
        fig.update_layout(
            height=300, margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0", yaxis=dict(autorange="reversed"),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)
else:
    st.markdown(
        """
        <div style="text-align:center; padding: 3rem; color: #64748b;">
            <div style="font-size: 4rem;">🛡️</div>
            <h3>No incidents yet</h3>
            <p>Go to <strong>Live SOC</strong> to process your first alert,
            or <strong>Alert Queue</strong> to load sample data.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ── Quick Actions ─────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("Quick Start")
qa1, qa2, qa3 = st.columns(3)
with qa1:
    st.markdown(
        "**🚀 Live SOC**\n\nProcess a real-time alert through all AI agents "
        "and watch the incident response unfold step by step."
    )
    if st.button("Open Live SOC →", use_container_width=True):
        st.switch_page("pages/1_Live_SOC.py")

with qa2:
    st.markdown(
        "**📥 Alert Queue**\n\nLoad alerts from JSON files, paste raw CEF/Splunk "
        "events, or use the built-in sample alerts for a demo."
    )
    if st.button("Open Alert Queue →", use_container_width=True):
        st.switch_page("pages/3_Alert_Queue.py")

with qa3:
    st.markdown(
        "**⚙️ Settings**\n\nConfigure your AI provider (Gemini / Claude / GPT), "
        "enter API keys, select model, and test the connection."
    )
    if st.button("Open Settings →", use_container_width=True):
        st.switch_page("pages/5_Settings.py")
