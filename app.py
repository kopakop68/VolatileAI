"""VolatileAI — AI-Powered Memory Forensics Investigation Platform."""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st

from config import APP_NAME, APP_VERSION, APP_TAGLINE
from core.volatility_engine import VolatilityEngine
from core.anomaly_detector import AnomalyDetector
from core.mitre_mapper import MitreMapper
from core.ai_engine import AIEngine
from core.scenario_loader import ScenarioLoader


def init_session_state():
    defaults = {
        "vol_engine": VolatilityEngine(),
        "detector": AnomalyDetector(),
        "mitre_mapper": MitreMapper(),
        "ai_engine": AIEngine(),
        "scenario_loader": ScenarioLoader(),
        "evidence_loaded": False,
        "evidence_info": None,
        "current_scenario": None,
        "findings": [],
        "plugin_results": {},
        "analysis_complete": False,
        "chat_history": [],
        "analysis_status": {
            "state": "idle",
            "done": 0,
            "total": 0,
            "current_plugin": "",
            "phase": "",
            "progress_pct": 0,
            "eta_sec": None,
            "started_at": None,
            "error": "",
            "summary": None,
            "result_payload": None,
            "applied": False,
        },
        "analysis_task_thread": None,
        "analysis_lock": threading.Lock(),
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def load_css():
    css_path = Path(__file__).parent / "ui" / "styles" / "theme.css"
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def main():
    st.set_page_config(
        page_title=APP_NAME,
        page_icon="VA",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    load_css()
    init_session_state()

    with st.sidebar:
        st.markdown(
            f"""<div style='text-align:center;padding:1rem 0'>
            <div style='font-size:1.3rem;font-weight:800;color:#f1f5f9;letter-spacing:-0.02em'>
                {APP_NAME}
            </div>
            <div style='font-size:0.7rem;color:#64748b;margin-top:2px'>{APP_TAGLINE}</div>
            <div style='font-size:0.65rem;color:#475569;margin-top:4px'>v{APP_VERSION}</div>
            </div>""",
            unsafe_allow_html=True,
        )

        st.divider()

        page = st.radio(
            "Navigation",
            [
                "Home",
                "Dashboard",
                "Process Analysis",
                "Network Analysis",
                "MITRE ATT&CK",
                "Timeline",
                "AI Analyst",
                "IOC Summary",
                "Reports",
            ],
            label_visibility="collapsed",
        )

        st.divider()

        vol_avail = st.session_state.vol_engine.is_volatility_available
        ai_status = st.session_state.ai_engine.provider_status()

        st.markdown("<div style='font-size:0.75rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px'>System Status</div>", unsafe_allow_html=True)
        analysis_state = st.session_state.get("analysis_status", {}).get("state", "idle")
        evidence_label = (
            "Loading…"
            if analysis_state == "running"
            else ("Loaded" if st.session_state.evidence_loaded else "None")
        )

        st.markdown(
            f"<div style='font-size:0.82rem;color:#94a3b8;line-height:1.8'>"
            f"Volatility 3: {'Ready' if vol_avail else 'Not installed'}<br>"
            f"AI Provider: {ai_status['message']}<br>"
            f"Evidence: {evidence_label}"
            f"</div>",
            unsafe_allow_html=True,
        )

    if "Home" in page:
        from ui.pages.home import render_home
        render_home()
    elif "Dashboard" in page:
        from ui.pages.dashboard import render_dashboard
        render_dashboard()
    elif "Process" in page:
        from ui.pages.process_analysis import render_process_analysis
        render_process_analysis()
    elif "Network" in page:
        from ui.pages.network_analysis import render_network_analysis
        render_network_analysis()
    elif "MITRE" in page:
        from ui.pages.mitre_page import render_mitre
        render_mitre()
    elif "Timeline" in page:
        from ui.pages.timeline_page import render_timeline
        render_timeline()
    elif "AI Analyst" in page:
        from ui.pages.ai_chat import render_ai_chat
        render_ai_chat()
    elif "IOC" in page:
        from ui.pages.ioc_summary import render_ioc_summary
        render_ioc_summary()
    elif "Report" in page:
        from ui.pages.reports_page import render_reports
        render_reports()


if __name__ == "__main__":
    main()
