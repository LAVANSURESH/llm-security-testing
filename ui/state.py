"""Shared session-state helpers used across all Streamlit pages."""

import os
import streamlit as st


PROVIDER_DEFAULTS = {
    "gemini": "gemini-2.0-flash",
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
}

PROVIDER_ENV_KEYS = {
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

PROVIDER_COLORS = {
    "gemini": "#4285F4",
    "anthropic": "#D97706",
    "openai": "#10B981",
}

PRIORITY_COLORS = {
    "P1": "#EF4444",
    "P2": "#F97316",
    "P3": "#EAB308",
    "P4": "#22C55E",
}

SEVERITY_COLORS = {
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#EAB308",
    "low": "#22C55E",
}


def init_state():
    """Initialize all session state keys with defaults."""
    defaults = {
        "provider": _detect_env_provider(),
        "api_key": _detect_env_key(),
        "model": None,
        "incidents": [],
        "processed_alert_ids": set(),
        "alert_queue": [],
        "soc_metrics": {},
        "last_error": None,
        "connection_ok": False,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

    # Derive model from provider if not set
    if not st.session_state.get("model"):
        st.session_state["model"] = PROVIDER_DEFAULTS.get(
            st.session_state["provider"], "claude-sonnet-4-6"
        )


def _detect_env_provider() -> str:
    for provider, env_key in PROVIDER_ENV_KEYS.items():
        if os.getenv(env_key):
            return provider
    return "anthropic"


def _detect_env_key() -> str:
    provider = _detect_env_provider()
    return os.getenv(PROVIDER_ENV_KEYS[provider], "")


def get_orchestrator():
    """Build a SOCOrchestrator from current session state (cached per session)."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from soc.orchestrator.soc_orchestrator import SOCOrchestrator

    provider = st.session_state.get("provider", "anthropic")
    api_key = st.session_state.get("api_key", "")
    model = st.session_state.get("model") or PROVIDER_DEFAULTS.get(provider)

    if not api_key:
        raise ValueError(f"No API key set for provider '{provider}'. Go to Settings.")

    return SOCOrchestrator(model=model, api_key=api_key, provider=provider)


def add_incident(incident):
    """Add a processed incident to session state (deduped by id)."""
    existing_ids = {inc.id for inc in st.session_state.incidents}
    if incident.id not in existing_ids:
        st.session_state.incidents.insert(0, incident)
        st.session_state.processed_alert_ids.add(incident.alerts[0].id if incident.alerts else "")


def compute_metrics() -> dict:
    incidents = st.session_state.incidents
    if not incidents:
        return {
            "total": 0, "p1": 0, "p2": 0, "p3": 0, "p4": 0,
            "avg_risk": 0.0, "open": 0, "contained": 0,
        }
    by_priority = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    by_status = {"open": 0, "investigating": 0, "contained": 0, "resolved": 0}
    total_risk = 0.0
    for inc in incidents:
        by_priority[inc.priority] = by_priority.get(inc.priority, 0) + 1
        by_status[inc.status] = by_status.get(inc.status, 0) + 1
        total_risk += inc.risk_score
    return {
        "total": len(incidents),
        "p1": by_priority.get("P1", 0),
        "p2": by_priority.get("P2", 0),
        "p3": by_priority.get("P3", 0),
        "p4": by_priority.get("P4", 0),
        "avg_risk": round(total_risk / len(incidents), 1),
        "open": by_status.get("open", 0) + by_status.get("investigating", 0),
        "contained": by_status.get("contained", 0) + by_status.get("resolved", 0),
    }


def sidebar_config():
    """Render the sidebar provider/model selector, return (provider, model)."""
    with st.sidebar:
        st.markdown("## ⚙️ SOC Configuration")

        provider = st.selectbox(
            "AI Provider",
            options=["gemini", "anthropic", "openai"],
            index=["gemini", "anthropic", "openai"].index(
                st.session_state.get("provider", "anthropic")
            ),
            format_func=lambda p: {
                "gemini": "🟢 Google Gemini",
                "anthropic": "🟠 Anthropic Claude",
                "openai": "🟩 OpenAI GPT",
            }[p],
            key="sidebar_provider",
        )

        if provider != st.session_state.get("provider"):
            st.session_state["provider"] = provider
            st.session_state["model"] = PROVIDER_DEFAULTS[provider]
            st.session_state["api_key"] = os.getenv(PROVIDER_ENV_KEYS[provider], "")

        model = st.text_input(
            "Model",
            value=st.session_state.get("model") or PROVIDER_DEFAULTS[provider],
            key="sidebar_model",
        )
        st.session_state["model"] = model

        api_key = st.text_input(
            "API Key",
            value=st.session_state.get("api_key", ""),
            type="password",
            placeholder=f"Your {provider} API key…",
            key="sidebar_api_key",
        )
        st.session_state["api_key"] = api_key

        st.divider()
        st.markdown("### 📊 Session Stats")
        metrics = compute_metrics()
        col1, col2 = st.columns(2)
        col1.metric("Incidents", metrics["total"])
        col2.metric("Avg Risk", f"{metrics['avg_risk']}/10")
        col1.metric("P1 Critical", metrics["p1"])
        col2.metric("Open", metrics["open"])

        st.divider()
        st.caption("AI-Powered SOC · Autonomous Agents")

    return provider, model
