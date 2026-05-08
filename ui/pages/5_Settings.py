"""
Settings — configure AI provider, API keys, model, and test connection.
"""

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.state import init_state, sidebar_config, PROVIDER_DEFAULTS, PROVIDER_ENV_KEYS

st.set_page_config(page_title="Settings | AI SOC", page_icon="⚙️", layout="wide")
init_state()
sidebar_config()

st.title("⚙️ Settings")
st.caption("Configure AI provider, API keys, and model preferences.")

# ── Provider Configuration ────────────────────────────────────────────────────
st.subheader("🤖 AI Provider")

PROVIDERS = {
    "gemini": {
        "name": "Google Gemini",
        "icon": "🟢",
        "env_key": "GEMINI_API_KEY",
        "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "description": "Google's latest Gemini models. Fast and cost-effective.",
        "key_hint": "Starts with 'AI...' — get it at aistudio.google.com",
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "icon": "🟠",
        "env_key": "ANTHROPIC_API_KEY",
        "models": ["claude-sonnet-4-6", "claude-opus-4-7", "claude-haiku-4-5-20251001"],
        "description": "Anthropic's Claude family. Excellent for complex reasoning.",
        "key_hint": "Starts with 'sk-ant-...' — get it at console.anthropic.com",
    },
    "openai": {
        "name": "OpenAI GPT",
        "icon": "🟩",
        "env_key": "OPENAI_API_KEY",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "description": "OpenAI's GPT-4 family. Widely used, strong tool use.",
        "key_hint": "Starts with 'sk-...' — get it at platform.openai.com",
    },
}

# Provider cards
cols = st.columns(3)
current_provider = st.session_state.get("provider", "anthropic")

for col, (pkey, pinfo) in zip(cols, PROVIDERS.items()):
    with col:
        is_selected = pkey == current_provider
        border_style = "2px solid #38bdf8" if is_selected else "1px solid #334155"
        env_key_value = os.getenv(pinfo["env_key"], "")

        st.markdown(
            f"""
            <div style="background:#1e293b;border-radius:10px;padding:1.2rem;
                        border:{border_style};min-height:140px">
                <h4 style="color:#f8fafc;margin:0">{pinfo["icon"]} {pinfo["name"]}</h4>
                <p style="color:#94a3b8;font-size:0.85rem;margin:0.4rem 0">{pinfo["description"]}</p>
                <p style="color:{'#22C55E' if env_key_value else '#64748b'};font-size:0.8rem;margin:0">
                    {'✅ Env key detected' if env_key_value else '⚪ No env key found'}
                </p>
                {"<p style='color:#38bdf8;font-size:0.8rem;margin:0'>← Active</p>" if is_selected else ""}
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button(f"Use {pinfo['name']}", key=f"select_{pkey}", use_container_width=True):
            st.session_state["provider"] = pkey
            st.session_state["model"] = PROVIDER_DEFAULTS[pkey]
            env_val = os.getenv(pinfo["env_key"], "")
            if env_val:
                st.session_state["api_key"] = env_val
            st.rerun()

st.markdown("---")

# ── Key and Model Config ──────────────────────────────────────────────────────
st.subheader("🔑 API Key & Model")

pinfo = PROVIDERS[current_provider]
st.caption(f"Configuring: **{pinfo['icon']} {pinfo['name']}** · {pinfo['key_hint']}")

col_key, col_model = st.columns([2, 1])

with col_key:
    current_key = st.session_state.get("api_key", "")
    env_detected = os.getenv(pinfo["env_key"], "")

    if env_detected and not current_key:
        st.session_state["api_key"] = env_detected
        current_key = env_detected

    new_key = st.text_input(
        f"{pinfo['name']} API Key",
        value=current_key,
        type="password",
        placeholder=pinfo["key_hint"],
        help="This key is stored only in your browser session and never persisted.",
    )
    if new_key != current_key:
        st.session_state["api_key"] = new_key

    if env_detected:
        st.caption(f"✅ `{pinfo['env_key']}` env var detected and pre-filled.")
    else:
        st.caption(
            f"💡 You can also set `export {pinfo['env_key']}=your-key` in your shell "
            f"before launching the app."
        )

with col_model:
    model_options = pinfo["models"]
    current_model = st.session_state.get("model", PROVIDER_DEFAULTS[current_provider])
    if current_model not in model_options:
        model_options = [current_model] + model_options

    new_model = st.selectbox("Model", model_options, index=model_options.index(current_model))
    if new_model != current_model:
        st.session_state["model"] = new_model

    st.caption(
        {
            "gemini-2.0-flash": "⚡ Fast, recommended",
            "gemini-1.5-pro": "🔬 More capable, slower",
            "claude-sonnet-4-6": "⚡ Fast, recommended",
            "claude-opus-4-7": "🔬 Most capable, slower",
            "claude-haiku-4-5-20251001": "🐇 Fastest, cheapest",
            "gpt-4o": "⚡ Fast, recommended",
            "gpt-4o-mini": "🐇 Fastest, cheapest",
            "gpt-4-turbo": "🔬 Capable, slower",
        }.get(new_model, "")
    )

st.markdown("---")

# ── Connection Test ───────────────────────────────────────────────────────────
st.subheader("🔌 Test Connection")
st.caption("Send a minimal test request to verify your API key and model work correctly.")

if st.button("🧪 Test Connection", type="primary"):
    api_key = st.session_state.get("api_key", "")
    model = st.session_state.get("model", PROVIDER_DEFAULTS[current_provider])

    if not api_key:
        st.error("No API key set. Enter one above first.")
    else:
        with st.spinner("Testing connection…"):
            try:
                if current_provider == "anthropic":
                    import anthropic
                    client = anthropic.Anthropic(api_key=api_key)
                    resp = client.messages.create(
                        model=model,
                        max_tokens=50,
                        messages=[{"role": "user", "content": "Reply with just: SOC_TEST_OK"}],
                    )
                    reply = resp.content[0].text.strip()

                elif current_provider == "openai":
                    from openai import OpenAI
                    client = OpenAI(api_key=api_key)
                    resp = client.chat.completions.create(
                        model=model,
                        max_tokens=50,
                        messages=[{"role": "user", "content": "Reply with just: SOC_TEST_OK"}],
                    )
                    reply = resp.choices[0].message.content.strip()

                elif current_provider == "gemini":
                    from google import genai as google_genai
                    from google.genai import types as gtypes
                    client = google_genai.Client(api_key=api_key)
                    resp = client.models.generate_content(
                        model=model,
                        contents="Reply with just: SOC_TEST_OK",
                        config=gtypes.GenerateContentConfig(max_output_tokens=50),
                    )
                    reply = resp.text.strip()

                st.success(f"✅ Connection successful! Model responded: `{reply[:80]}`")
                st.session_state["connection_ok"] = True

            except Exception as e:
                st.error(f"❌ Connection failed: {e}")
                st.session_state["connection_ok"] = False

st.markdown("---")

# ── Environment Info ──────────────────────────────────────────────────────────
st.subheader("🌍 Environment")

env_col1, env_col2 = st.columns(2)
with env_col1:
    st.markdown("**Detected environment variables:**")
    for pkey, pinfo in PROVIDERS.items():
        val = os.getenv(pinfo["env_key"])
        if val:
            masked = val[:8] + "***" + val[-4:] if len(val) > 12 else "***"
            st.markdown(f"- ✅ `{pinfo['env_key']}` = `{masked}`")
        else:
            st.markdown(f"- ⚪ `{pinfo['env_key']}` not set")

with env_col2:
    st.markdown("**Current session configuration:**")
    st.markdown(f"- Provider: `{st.session_state.get('provider','—')}`")
    st.markdown(f"- Model: `{st.session_state.get('model','—')}`")
    key = st.session_state.get("api_key", "")
    key_display = key[:8] + "***" if len(key) > 8 else ("(empty)" if not key else "***")
    st.markdown(f"- API Key: `{key_display}`")
    st.markdown(f"- Incidents in session: `{len(st.session_state.get('incidents',[]))}`")
    st.markdown(f"- Alerts in queue: `{len(st.session_state.get('alert_queue',[]))}`")

st.markdown("---")

# ── Advanced Options ──────────────────────────────────────────────────────────
with st.expander("🔧 Advanced Options"):
    st.markdown("**Session Management**")
    sc1, sc2 = st.columns(2)
    if sc1.button("🗑️ Clear All Incidents", use_container_width=True):
        st.session_state["incidents"] = []
        st.session_state["processed_alert_ids"] = set()
        st.success("Cleared all incidents from session.")

    if sc2.button("🗑️ Clear Alert Queue", use_container_width=True):
        st.session_state["alert_queue"] = []
        st.success("Alert queue cleared.")

    st.markdown("**Quick Setup Commands**")
    st.code(
        f"# Set environment variables (add to ~/.bashrc or ~/.zshrc)\n"
        f"export GEMINI_API_KEY=your-gemini-key\n"
        f"export ANTHROPIC_API_KEY=your-anthropic-key\n"
        f"export OPENAI_API_KEY=your-openai-key\n\n"
        f"# Launch the UI\n"
        f"streamlit run ui/app.py",
        language="bash",
    )

    st.markdown("**CLI Alternative**")
    st.code(
        f"# Run without the UI\n"
        f"python soc/main.py --provider {current_provider} --model {st.session_state.get('model','?')} --limit 3",
        language="bash",
    )
