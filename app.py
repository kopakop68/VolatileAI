"""VolatileAI — AI-Powered Memory Forensics Investigation Platform."""

import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
import streamlit.components.v1 as components

from config import APP_NAME, GITHUB_REPO_URL
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
        "selected_page": "Home",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def load_css():
    css_path = Path(__file__).parent / "ui" / "styles" / "theme.css"
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def _query_param(name: str, default: str = "") -> str:
    value = st.query_params.get(name, default)
    if isinstance(value, list):
        value = value[0] if value else default
    return str(value).strip()


def _inject_top_guide_button(href: str):
    safe_href = json.dumps(href)
    components.html(
        f"""
        <script>
        (function() {{
            const doc = window.parent.document;
            const buttonId = "va-guide-top-btn";
            const href = {safe_href};
            let button = doc.getElementById(buttonId);

            if (!button) {{
                button = doc.createElement("a");
                button.id = buttonId;
                button.textContent = "Guide";
                button.target = "_self";
                Object.assign(button.style, {{
                    position: "fixed",
                    top: "8px",
                    right: "64px",
                    zIndex: "2147483647",
                    display: "inline-flex",
                    alignItems: "center",
                    background: "rgba(15, 23, 42, 0.95)",
                    border: "1px solid rgba(56, 189, 248, 0.55)",
                    borderRadius: "8px",
                    padding: "5px 11px",
                    fontSize: "12px",
                    fontWeight: "600",
                    color: "#cbd5e1",
                    textDecoration: "none",
                    backdropFilter: "blur(4px)",
                    boxShadow: "0 6px 20px rgba(15, 23, 42, 0.28)"
                }});
                button.addEventListener("mouseenter", () => {{
                    button.style.borderColor = "#38bdf8";
                    button.style.color = "#38bdf8";
                }});
                button.addEventListener("mouseleave", () => {{
                    button.style.borderColor = "rgba(56, 189, 248, 0.55)";
                    button.style.color = "#cbd5e1";
                }});
                doc.body.appendChild(button);
            }}
            button.href = href;
        }})();
        </script>
        """,
        height=0,
        width=0,
    )


def main():
    st.set_page_config(
        page_title=APP_NAME,
        page_icon="VA",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "Get Help": None,
            "Report a bug": None,
            "About": None,
        },
    )

    load_css()
    init_session_state()

    # Top guide link is driven by query params so it behaves like a global entrypoint.
    docs_param = _query_param("docs", "0").lower()
    show_docs = docs_param in {"1", "true", "yes"}
    page_param = _query_param("page", "").lower()

    pages = [
        "Home",
        "Dashboard",
        "Process Analysis",
        "Network Analysis",
        "MITRE ATT&CK",
        "Timeline",
        "AI Analyst",
        "IOC Summary",
        "Reports",
    ]
    page_aliases = {
        "home": "Home",
        "dashboard": "Dashboard",
        "process": "Process Analysis",
        "process-analysis": "Process Analysis",
        "network": "Network Analysis",
        "network-analysis": "Network Analysis",
        "mitre": "MITRE ATT&CK",
        "timeline": "Timeline",
        "ai": "AI Analyst",
        "ai-analyst": "AI Analyst",
        "ioc": "IOC Summary",
        "ioc-summary": "IOC Summary",
        "reports": "Reports",
    }
    page_slug_by_name = {
        "Home": "home",
        "Dashboard": "dashboard",
        "Process Analysis": "process-analysis",
        "Network Analysis": "network-analysis",
        "MITRE ATT&CK": "mitre",
        "Timeline": "timeline",
        "AI Analyst": "ai-analyst",
        "IOC Summary": "ioc-summary",
        "Reports": "reports",
    }
    requested_page = page_aliases.get(page_param)
    if requested_page in pages:
        st.session_state.selected_page = requested_page
    current_page_slug = page_slug_by_name.get(st.session_state.get("selected_page", "Home"), "home")
    back_page_slug = page_param if page_param in page_aliases else current_page_slug
    guide_href = f"?docs=1&page={back_page_slug}&docs_page=quick-start"
    back_href = f"?docs=0&page={back_page_slug}"
    _inject_top_guide_button(guide_href)

    st.markdown(
        f"""
        <style>
        footer {{
            visibility: hidden;
        }}
        [data-testid="stMainMenu"] a[href*="streamlit.io"] {{
            display: none !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Keep analysis state coherent across all pages: when background work
    # completes, apply payload once even if the user never visits Home first.
    try:
        from ui.pages.home import _apply_completed_analysis_if_needed
        _apply_completed_analysis_if_needed()
    except Exception:
        # Sidebar/rendering should not fail if page helpers are unavailable.
        pass

    with st.sidebar:
        st.markdown(
            f"""<div style='text-align:center;padding:1rem 0'>
            <div style='font-size:1.3rem;font-weight:800;color:#f1f5f9;letter-spacing:-0.02em'>
                <a href='?docs=0&page=home' style='color:#f1f5f9;text-decoration:none'>{APP_NAME}</a>
            </div>
            </div>""",
            unsafe_allow_html=True,
        )

        st.divider()

        page = st.radio(
            "Navigation",
            pages,
            label_visibility="collapsed",
            key="selected_page",
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

    if show_docs:
        st.markdown(
            "<div style='margin:0.15rem 0 0.7rem 0'>"
            f"<a href='{back_href}' style='display:inline-block;padding:0.4rem 0.75rem;border:1px solid #38bdf8;border-radius:8px;color:#38bdf8;text-decoration:none;font-size:0.82rem;font-weight:600'>"
            "Back to Home</a>"
            "</div>",
            unsafe_allow_html=True,
        )
        from ui.pages.documentation_page import render_documentation
        render_documentation()
        st.markdown(
            f"<div style='margin-top:0.8rem'><a href='{back_href}' style='color:#38bdf8;text-decoration:none;font-weight:600'>Close Documentation</a></div>",
            unsafe_allow_html=True,
        )
    elif "Home" in page:
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

    st.markdown("<div style='height:1.4rem'></div>", unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class='project-footer'>
            <div class='project-footer__name'>
                <a href='{GITHUB_REPO_URL}' target='_blank' style='color:#38bdf8;text-decoration:none'>
                    Made by Kopal Chaturvedi
                </a>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
