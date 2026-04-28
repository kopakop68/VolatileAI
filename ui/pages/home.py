"""VolatileAI — Home / Evidence Loader page."""

import time
import threading
import traceback
from html import escape

import streamlit as st
from config import VOLATILITY_PLUGINS_WINDOWS
from ui.components.metrics import info_banner


PLUGIN_LABELS = {
    "windows.pslist": "Process List (pslist) - fast",
    "windows.pstree": "Process Tree (pstree) - fast",
    "windows.cmdline": "Command Lines (cmdline) - fast",
    "windows.dlllist": "DLL List (dlllist) - medium",
    "windows.netscan": "Network Connections (netscan) - fast",
    "windows.malfind": "Injection Scanner (malfind) - SLOW ~60s",
    "windows.malware.malfind": "Injection Scanner (malfind) - SLOW ~60s",
    "windows.handles": "Handles (handles) - VERY SLOW ~90s",
    "windows.svcscan": "Services (svcscan) - fast",
    "windows.filescan": "File Scan (filescan) - SLOW ~45s",
    "windows.registry.hivelist": "Registry Hives (hivelist) - fast",
}

_MALFIND_PLUGIN = (
    "windows.malware.malfind"
    if "windows.malware.malfind" in VOLATILITY_PLUGINS_WINDOWS
    else "windows.malfind"
)

PRESET_PROFILES = {
    "Quick Triage (no slow plugins)": [
        "windows.pslist",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.svcscan",
        "windows.registry.hivelist",
    ],
    "Full Analysis (all plugins)": VOLATILITY_PLUGINS_WINDOWS,
    "Network Focus": ["windows.pslist", "windows.netscan"],
    "Injection Focus": ["windows.pslist", "windows.pstree", _MALFIND_PLUGIN, "windows.dlllist"],
    "Custom": None,
}


def _start_background_analysis(file_path: str, evidence, plugins: list = None):
    status = st.session_state.analysis_status
    lock = st.session_state.analysis_lock
    vol_engine = st.session_state.vol_engine
    detector = st.session_state.detector

    with lock:
        status.update(
            {
                "state": "running",
                "done": 0,
                "total": 0,
                "current_plugin": "",
                "phase": "starting",
                "progress_pct": 0,
                "eta_sec": None,
                "started_at": time.time(),
                "error": "",
                "summary": None,
                "result_payload": None,
                "applied": False,
            }
        )

    def _worker():
        try:
            def _on_progress(done: int, total: int, plugin_name: str, phase: str):
                started_at = status.get("started_at") or time.time()
                elapsed = max(time.time() - started_at, 0.01)
                avg_per_plugin = elapsed / max(done, 1)
                remaining = max(total - done, 0)
                eta_sec = int(avg_per_plugin * remaining)
                pct = int((done / max(total, 1)) * 100)

                with lock:
                    status.update(
                        {
                            "done": done,
                            "total": total,
                            "current_plugin": plugin_name,
                            "phase": phase,
                            "progress_pct": min(pct, 99 if phase == "starting" else 100),
                            "eta_sec": eta_sec,
                        }
                    )

            plugin_results = vol_engine.run_all_plugins(
                file_path,
                progress_callback=_on_progress,
                plugins=plugins,
            )
            findings = detector.analyze_all(plugin_results)
            confirmed_mitre = ", ".join(sorted({t for f in findings for t in f.mitre_techniques}))

            success_count = sum(1 for result in plugin_results.values() if result.success)
            non_empty_count = sum(1 for result in plugin_results.values() if result.success and result.row_count > 0)
            failed = [
                f"{name}: {result.error or 'Unknown error'}"
                for name, result in plugin_results.items()
                if not result.success
            ]

            findings_text = "\n".join(
                f"- [{f.risk_level.upper()}] {f.title}: {f.description}"
                for f in findings[:20]
            )
            if not findings_text:
                findings_text = "No detections were produced by the current plugin output."

            with lock:
                status.update(
                    {
                        "state": "completed",
                        "done": status.get("total", 0),
                        "phase": "completed",
                        "progress_pct": 100,
                        "eta_sec": 0,
                        "summary": {
                            "success_count": success_count,
                            "total_plugins": len(plugin_results),
                            "non_empty_count": non_empty_count,
                            "failed": failed,
                        },
                        "result_payload": {
                            "plugin_results": plugin_results,
                            "findings": findings,
                            "findings_text": findings_text,
                            "evidence_filename": evidence.filename,
                        },
                    }
                )
        except Exception as exc:
            with lock:
                status.update(
                    {
                        "state": "failed",
                        "phase": "failed",
                        "error": f"{type(exc).__name__}: {exc}",
                        "result_payload": {
                            "traceback": traceback.format_exc(),
                        },
                    }
                )

    thread = threading.Thread(target=_worker, daemon=True, name="volatileai-analysis")
    st.session_state.analysis_task_thread = thread
    thread.start()


def _apply_completed_analysis_if_needed():
    status = st.session_state.analysis_status
    if status.get("state") != "completed" or status.get("applied"):
        return

    payload = status.get("result_payload") or {}
    plugin_results = payload.get("plugin_results", {})
    findings = payload.get("findings", [])
    findings_text = payload.get("findings_text", "")
    evidence_filename = payload.get("evidence_filename", "Evidence")

    st.session_state.plugin_results = plugin_results
    st.session_state.findings = findings
    st.session_state.evidence_loaded = True
    st.session_state.current_scenario = None
    st.session_state.analysis_complete = True

    confirmed_mitre = ", ".join(sorted({t for finding in findings for t in getattr(finding, "mitre_techniques", [])}))
    st.session_state.ai_engine.set_context(findings_text, f"Evidence: {evidence_filename}", confirmed_mitre)
    status["applied"] = True


def _render_analysis_progress(allow_full_rerun: bool = False):
    status = st.session_state.analysis_status
    state = status.get("state", "idle")
    if state not in {"running", "completed", "failed"}:
        return

    st.markdown(
        """
        <style>
        .va-loader-wrap { margin: 0.35rem 0 0.65rem 0; }
        .va-loader { display:flex; gap:6px; align-items:center; }
        .va-dot { width:8px; height:8px; border-radius:50%; background:#38bdf8; opacity:0.35;
                  animation: vaPulse 1.15s infinite ease-in-out; }
        .va-dot:nth-child(2) { animation-delay: 0.18s; }
        .va-dot:nth-child(3) { animation-delay: 0.36s; }
        @keyframes vaPulse {
            0%, 80%, 100% { transform: scale(0.85); opacity: 0.28; }
            40% { transform: scale(1.15); opacity: 1; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if state == "running":
        st.markdown(
            """
            <div class='va-loader-wrap'>
              <div style='color:#94a3b8;font-size:0.83rem;margin-bottom:6px'>Running Volatility plugins in background</div>
              <div class='va-loader'>
                <div class='va-dot'></div><div class='va-dot'></div><div class='va-dot'></div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        pct = int(status.get("progress_pct", 0))
        done = int(status.get("done", 0))
        total = int(status.get("total", 0))
        plugin_name = status.get("current_plugin", "")
        eta_sec = status.get("eta_sec")
        eta_text = f" · ETA ~ {eta_sec}s" if isinstance(eta_sec, int) else ""

        st.progress(pct, text=f"Plugin progress: {pct}%")
        if plugin_name:
            st.markdown(
                f"<div style='color:#94a3b8;font-size:0.82rem'>"
                f"[{done}/{max(total, 1)}] {escape(plugin_name)}{eta_text}"
                f"</div>",
                unsafe_allow_html=True,
            )
        st.caption("You can switch tabs; plugin execution will continue.")
        if allow_full_rerun:
            time.sleep(1.1)
            st.rerun()

    elif state == "failed":
        st.error(f"Plugin execution failed: {status.get('error', 'Unknown error')}")
        trace = (status.get("result_payload") or {}).get("traceback")
        if trace:
            with st.expander("Error details", expanded=False):
                st.code(trace)

    elif state == "completed":
        summary = status.get("summary") or {}
        st.success("Plugin execution completed.")
        st.progress(100, text="Plugin progress: 100%")
        st.markdown(
            f"<div style='color:#94a3b8;font-size:0.82rem;margin-top:0.45rem'>"
            f"Plugin execution summary: {summary.get('success_count', 0)}/{summary.get('total_plugins', 0)} succeeded, "
            f"{summary.get('non_empty_count', 0)} returned data rows."
            f"</div>",
            unsafe_allow_html=True,
        )
        failed = summary.get("failed") or []
        if failed:
            with st.expander("Plugin errors", expanded=False):
                for item in failed:
                    st.markdown(f"- {item}")


def _render_analysis_progress_live():
    """Render progress with minimal UI flicker while background analysis runs."""
    status = st.session_state.analysis_status
    state = status.get("state", "idle")

    if state != "running":
        _render_analysis_progress(allow_full_rerun=False)
        return

    # Streamlit fragment reruns only this block on interval, avoiding full-page
    # rerenders that can cause visible dim/flash during long analysis runs.
    if hasattr(st, "fragment"):
        @st.fragment(run_every="1s")
        def _progress_fragment():
            _render_analysis_progress(allow_full_rerun=False)

        _progress_fragment()
        return

    # Fallback for older Streamlit versions.
    _render_analysis_progress(allow_full_rerun=True)


def _render_evidence_details(evidence):
    if not evidence:
        return

    st.markdown(
        (
            f"<div style='background:#0f172a;border:1px solid #1e293b;border-radius:12px;"
            f"padding:1rem 1.2rem;margin-top:0.8rem;margin-bottom:0.8rem'>"
            f"<div style='font-weight:700;color:#38bdf8;margin-bottom:10px;font-size:0.95rem'>"
            f"Evidence Details"
            f"</div>"
            f"<div style='display:grid;grid-template-columns:minmax(120px,180px) 1fr;gap:8px 14px;"
            f"color:#e2e8f0;font-size:0.86rem;align-items:start'>"
            f"<div style='color:#64748b'>Filename</div>"
            f"<div style='font-weight:600;overflow-wrap:anywhere'>{escape(evidence.filename)}</div>"
            f"<div style='color:#64748b'>Size</div>"
            f"<div>{escape(evidence.size_human)}</div>"
            f"<div style='color:#64748b'>Format</div>"
            f"<div><code>{escape(evidence.format)}</code></div>"
            f"<div style='color:#64748b'>MD5</div>"
            f"<div style='font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,\"Liberation Mono\",monospace;"
            f"font-size:0.78rem;overflow-wrap:anywhere;word-break:break-word'>{escape(evidence.md5)}</div>"
            f"<div style='color:#64748b'>SHA-256</div>"
            f"<div style='font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,\"Liberation Mono\",monospace;"
            f"font-size:0.78rem;overflow-wrap:anywhere;word-break:break-word'>{escape(evidence.sha256)}</div>"
            f"</div>"
            f"</div>"
        ),
        unsafe_allow_html=True,
    )


def _render_hero():
    st.markdown("""
    <div style='text-align:center;padding:2.2rem 1rem 1.2rem 1rem'>
        <div style='font-size:3.1rem;font-weight:900;
            background:linear-gradient(120deg,#06b6d4 0%,#22d3ee 35%,#60a5fa 70%,#818cf8 100%);
            -webkit-background-clip:text;-webkit-text-fill-color:transparent;
            letter-spacing:-0.02em'>
            VolatileAI
        </div>
        <div style='font-size:1.02rem;color:#94a3b8;margin-top:0.35rem;font-weight:500;letter-spacing:0.02em'>
            Investigate memory evidence faster, map attacker behavior, act with confidence.
        </div>
    </div>
    <div style='border-bottom:1px solid #1e293b;margin:0 2rem 1.2rem 2rem'></div>
    """, unsafe_allow_html=True)


def _render_evidence_loader():
    st.markdown(
        "<h3 style='color:#f1f5f9;font-weight:700;margin-bottom:0.4rem'>"
        "Load Evidence File</h3>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color:#64748b;font-size:0.85rem;margin-bottom:1rem'>"
        "Load a real dump to run plugins and generate findings automatically.</p>",
        unsafe_allow_html=True,
    )

    status = st.session_state.analysis_status
    analysis_done = bool(st.session_state.get("analysis_complete")) or status.get("state") == "completed"

    if st.session_state.get("evidence_loaded") or analysis_done:
        st.markdown(
            "<div style='color:#94a3b8;font-size:0.9rem;margin-bottom:0.75rem'>"
            "Current evidence is loaded. Clear it first if you want to analyze a different dump."
            "</div>",
            unsafe_allow_html=True,
        )
        clear_col, _ = st.columns([1, 3])
        with clear_col:
            if st.button("Clear Current", width="stretch"):
                st.session_state.evidence_loaded = False
                st.session_state.evidence_info = None
                st.session_state.plugin_results = {}
                st.session_state.findings = []
                st.session_state.analysis_complete = False
                st.session_state.current_scenario = None
                st.session_state.chat_history = []
                st.session_state.analysis_status.update(
                    {
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
                    }
                )
                st.rerun()
        return

    if "evidence_file_path" not in st.session_state:
        st.session_state.evidence_file_path = ""

    file_path = st.text_input(
        "Evidence file path",
        placeholder="/path/to/memory.raw",
        key="evidence_file_path",
        label_visibility="collapsed",
    )

    if "plugin_preset" not in st.session_state:
        st.session_state.plugin_preset = "Quick Triage (no slow plugins)"
    if "plugin_preset_prev" not in st.session_state:
        st.session_state.plugin_preset_prev = st.session_state.plugin_preset
    if "selected_plugins" not in st.session_state:
        st.session_state.selected_plugins = list(PRESET_PROFILES["Quick Triage (no slow plugins)"])

    # Plugin selector
    with st.expander("Plugin Selection", expanded=False):
        preset = st.selectbox(
            "Preset profile",
            list(PRESET_PROFILES.keys()),
            index=list(PRESET_PROFILES.keys()).index(st.session_state.plugin_preset),
            key="plugin_preset",
        )
        preset_plugins = PRESET_PROFILES[preset]
        is_custom = preset_plugins is None

        if st.session_state.plugin_preset_prev != preset:
            st.session_state.plugin_preset_prev = preset
            if not is_custom:
                st.session_state.selected_plugins = list(preset_plugins)

        selected_plugins = st.multiselect(
            "Plugins to run",
            options=VOLATILITY_PLUGINS_WINDOWS,
            default=st.session_state.selected_plugins,
            format_func=lambda p: PLUGIN_LABELS.get(p, p),
            key="selected_plugins",
            disabled=(not is_custom),
            help="Plugins marked SLOW can take 45-90 seconds each on larger memory dumps.",
        )

        if not selected_plugins:
            st.warning("Select at least one plugin.")

        slow = {"windows.malfind", "windows.malware.malfind", "windows.handles", "windows.filescan"}
        chosen_slow = slow & set(selected_plugins)
        if chosen_slow:
            slow_names = ", ".join(sorted(PLUGIN_LABELS[p].split(" (")[0] for p in chosen_slow))
            st.caption(f"Slow plugins selected: {slow_names}. Expect longer wait.")

        if "windows.malfind" not in selected_plugins and "windows.malware.malfind" not in selected_plugins:
            st.caption("malfind excluded - injection findings will be unavailable.")

    analysis_running = status.get("state") == "running"

    if analysis_running:
        info_banner("Analysis is running in background. You can switch tabs safely.", "info")

    if not st.session_state.vol_engine.is_volatility_available:
        info_banner(
            "Volatility 3 is not installed in this environment. Run ./setup.sh to install dependencies, including volatility3.",
            "warning",
        )

    load_clicked = st.button(
        "Validate & Load",
        type="primary",
        width="stretch",
        disabled=analysis_running or analysis_done or not st.session_state.get("selected_plugins"),
    )

    if load_clicked:
        if not file_path or not file_path.strip():
            st.warning("Please enter a file path first.")
            return

        # Reuse the same app instance for new evidence without restarting Streamlit.
        st.session_state.plugin_results = {}
        st.session_state.findings = []
        st.session_state.analysis_complete = False
        st.session_state.current_scenario = None
        st.session_state.chat_history = []

        with st.spinner("Validating evidence file…"):
            evidence = st.session_state.vol_engine.validate_evidence(file_path.strip())

        if not evidence.is_valid:
            st.error(f"Invalid evidence file: **{evidence.filename}** — "
                     f"format `{evidence.format}` is not supported or file not found.")
            return

        st.session_state.evidence_info = evidence

        chosen = st.session_state.get("selected_plugins") or VOLATILITY_PLUGINS_WINDOWS
        _start_background_analysis(file_path.strip(), evidence, plugins=chosen)
        st.rerun()


def render_home():
    _apply_completed_analysis_if_needed()
    _render_hero()

    if st.session_state.get("evidence_loaded"):
        info_banner(
            "Evidence is loaded and ready. Navigate to the Dashboard to explore findings.",
            "success",
        )
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)

    # Keep evidence metadata visible across reruns and tab switches.
    if st.session_state.get("evidence_info"):
        _render_evidence_details(st.session_state.evidence_info)

    _render_evidence_loader()

    _render_analysis_progress_live()

    status = st.session_state.analysis_status
    if status.get("state") == "completed" and status.get("applied"):
        summary = status.get("summary") or {}
        success_count = summary.get("success_count", 0)
        non_empty_count = summary.get("non_empty_count", 0)

        if success_count == 0:
            info_banner(
                "Evidence loaded, but no Volatility plugins succeeded. Check plugin errors above and verify Volatility/profile support for this dump.",
                "warning",
            )
        elif non_empty_count == 0:
            info_banner(
                "Evidence loaded, but plugins returned no parsed rows. Dashboard may remain empty until plugin output is available.",
                "warning",
            )
        else:
            info_banner("Evidence loaded and analysis complete! Head to the Dashboard to review findings.", "success")
