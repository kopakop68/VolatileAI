"""AI Forensic Analyst chat page for VolatileAI."""

import streamlit as st
from ui.components.metrics import page_header, info_banner

SUGGESTED_QUESTIONS = [
    "What are the most suspicious processes found in memory?",
    "Are there any signs of code injection or process hollowing?",
    "Which network connections look potentially malicious?",
    "Summarize all indicators of compromise found so far.",
    "What persistence mechanisms were detected?",
    "Is there evidence of lateral movement in this memory dump?",
    "What DLLs appear to be side-loaded or injected?",
    "Can you correlate the findings into an attack timeline?",
    "What MITRE ATT&CK techniques are represented?",
    "What remediation steps do you recommend?",
]


def _render_chat_card(role: str, content: str):
    if role == "user":
        border = "#38bdf8"
        title = "User"
    else:
        border = "#818cf8"
        title = "AI Analyst"

    import re

    safe = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    safe = re.sub(r"\*\*(.+?)\*\*", r"<strong style='color:#f8fafc'>\1</strong>", safe)
    safe = re.sub(r"_(.+?)_", r"<em>\1</em>", safe)
    safe = safe.replace("\n", "<br>")

    st.markdown(
        f"""
        <div style='background:#0f172a;border:1px solid {border}33;border-left:3px solid {border};
            border-radius:12px;padding:0.85rem 1rem;margin:0.4rem 0;color:#e2e8f0;
            box-shadow:0 2px 10px rgba(0,0,0,0.15)'>
            <div style='color:{border};font-size:0.72rem;font-weight:700;letter-spacing:0.08em;
                text-transform:uppercase;margin-bottom:0.35rem'>{title}</div>
            <div style='color:#e2e8f0;font-size:0.92rem;line-height:1.65;overflow-wrap:anywhere'>{safe}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_ai_chat():
    page_header("AI Forensic Analyst", icon="")

    if "findings" not in st.session_state or not st.session_state.findings:
        info_banner("Load evidence first to interact with the AI analyst.", type_="warning")
        return

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    ai_engine = st.session_state.ai_engine
    scenario_id = st.session_state.get("current_scenario") or ""

    provider_status = ai_engine.provider_status()
    st.markdown(
        "<div style='display:flex;align-items:center;gap:6px;margin-bottom:0.8rem'>"
        f"<span style='width:8px;height:8px;border-radius:50%;background:{provider_status['dot']};display:inline-block'></span>"
        f"<span style='color:#94a3b8;font-size:0.85rem'>{provider_status['message']}</span>"
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("#### Quick Analysis")
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1.15])
    with col1:
        if st.button("Auto Summary", width="stretch"):
            with st.spinner("AI Analyst is analyzing findings..."):
                response = ai_engine.get_auto_analysis(scenario_id)
            st.session_state.chat_history.append({
                "role": "user",
                "content": "Summarize the findings and provide an overall assessment",
            })
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    with col2:
        if st.button("Attack Narrative", width="stretch"):
            with st.spinner("AI Analyst is analyzing findings..."):
                response = ai_engine.get_attack_narrative(scenario_id)
            st.session_state.chat_history.append({
                "role": "user",
                "content": "Construct a narrative of the attack based on the evidence",
            })
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    with col3:
        if st.button("IOC List", width="stretch"):
            with st.spinner("AI Analyst is analyzing findings..."):
                response = ai_engine.get_ioc_list(scenario_id)
            st.session_state.chat_history.append({
                "role": "user",
                "content": "List all indicators of compromise found in the evidence",
            })
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()
    with col4:
        if st.button("Fix Actions", width="stretch"):
            with st.spinner("AI Analyst is analyzing findings..."):
                response = ai_engine.get_recommendations(scenario_id)
            st.session_state.chat_history.append({
                "role": "user",
                "content": "What are your recommended remediation and response actions?",
            })
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            st.rerun()

    if st.session_state.chat_history and st.session_state.chat_history[-1]["role"] == "assistant":
        st.markdown("<div style='height:0.75rem'></div>", unsafe_allow_html=True)
        info_banner("Latest AI response is ready below.", type_="success")
        with st.container():
            _render_chat_card("assistant", st.session_state.chat_history[-1]["content"])

    st.markdown("---")

    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            _render_chat_card(msg["role"], msg["content"])

    if prompt := st.chat_input("Ask about the investigation..."):
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            _render_chat_card("user", prompt)

        response = ai_engine.ask(prompt, scenario_id)
        st.session_state.chat_history.append({"role": "assistant", "content": response})
        with st.chat_message("assistant"):
            _render_chat_card("assistant", response)

    if not st.session_state.chat_history:
        st.markdown("---")
        st.markdown("#### Suggested Questions")
        cols = st.columns(2)
        for i, question in enumerate(SUGGESTED_QUESTIONS):
            with cols[i % 2]:
                if st.button(question, key=f"sq_{i}", width="stretch"):
                    st.session_state.chat_history.append({"role": "user", "content": question})
                    response = ai_engine.ask(question, scenario_id)
                    st.session_state.chat_history.append({"role": "assistant", "content": response})
                    st.rerun()
