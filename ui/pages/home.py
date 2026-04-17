"""VolatileAI — Home / Evidence Loader page."""

import time
from html import escape

import streamlit as st
from ui.components.metrics import info_banner


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
        <div style='display:flex;justify-content:center;gap:8px;flex-wrap:wrap;margin:0.95rem auto 0 auto'>
            <span style='font-size:0.72rem;background:#0e7490;color:#cffafe;padding:4px 10px;border-radius:999px;border:1px solid #155e75'>Live Evidence</span>
            <span style='font-size:0.72rem;background:#1e3a8a;color:#dbeafe;padding:4px 10px;border-radius:999px;border:1px solid #1d4ed8'>Threat Findings</span>
            <span style='font-size:0.72rem;background:#3f3f46;color:#e4e4e7;padding:4px 10px;border-radius:999px;border:1px solid #52525b'>MITRE Mapping</span>
            <span style='font-size:0.72rem;background:#3f1d55;color:#f3e8ff;padding:4px 10px;border-radius:999px;border:1px solid #6b21a8'>AI Analysis</span>
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

    if "evidence_file_path" not in st.session_state:
        st.session_state.evidence_file_path = ""

    file_path = st.text_input(
        "Evidence file path",
        placeholder="/path/to/memory.raw",
        key="evidence_file_path",
        label_visibility="collapsed",
    )

    if st.session_state.get("evidence_loaded"):
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
                st.rerun()

    if not st.session_state.vol_engine.is_volatility_available:
        info_banner(
            "Volatility 3 is not installed in this environment. Run ./setup.sh to install dependencies, including volatility3.",
            "warning",
        )

    load_clicked = st.button("Validate & Load", type="primary", width="stretch")

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

        loader_box = st.empty()
        loader_box.markdown(
            """
            <div class='va-loader-wrap'>
              <div style='color:#94a3b8;font-size:0.83rem;margin-bottom:6px'>Running Volatility plugins</div>
              <div class='va-loader'>
                <div class='va-dot'></div><div class='va-dot'></div><div class='va-dot'></div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        progress = st.progress(0, text="Starting plugin execution…")
        status = st.empty()
        started_at = time.time()

        def _on_progress(done: int, total: int, plugin_name: str, phase: str):
            pct = int((done / max(total, 1)) * 100)
            elapsed = max(time.time() - started_at, 0.01)
            avg_per_plugin = elapsed / max(done, 1)
            remaining = max(total - done, 0)
            eta_sec = int(avg_per_plugin * remaining)

            if phase == "starting":
                status.markdown(
                    f"<div style='color:#94a3b8;font-size:0.82rem'>"
                    f"[{done + 1}/{total}] Starting <code>{escape(plugin_name)}</code>…"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                progress.progress(min(pct, 99), text=f"Plugin progress: {pct}%")
            else:
                status.markdown(
                    f"<div style='color:#94a3b8;font-size:0.82rem'>"
                    f"[{done}/{total}] Completed <code>{escape(plugin_name)}</code>"
                    f" · ETA ~ {eta_sec}s"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                progress.progress(pct, text=f"Plugin progress: {pct}%")

        plugin_results = st.session_state.vol_engine.run_all_plugins(
            file_path.strip(),
            progress_callback=_on_progress,
        )
        loader_box.empty()
        progress.progress(100, text="Plugin progress: 100%")
        status.markdown(
            "<div style='color:#22c55e;font-size:0.82rem'>Plugin execution completed.</div>",
            unsafe_allow_html=True,
        )

        success_count = sum(1 for result in plugin_results.values() if result.success)
        non_empty_count = sum(1 for result in plugin_results.values() if result.success and result.row_count > 0)
        failed = [f"{name}: {result.error or 'Unknown error'}" for name, result in plugin_results.items() if not result.success]

        st.markdown(
            f"<div style='color:#94a3b8;font-size:0.82rem;margin-top:0.6rem'>"
            f"Plugin execution summary: {success_count}/{len(plugin_results)} succeeded, "
            f"{non_empty_count} returned data rows."
            f"</div>",
            unsafe_allow_html=True,
        )

        if failed:
            with st.expander("Plugin errors", expanded=False):
                for item in failed:
                    st.markdown(f"- {item}")

        st.session_state.plugin_results = plugin_results
        st.session_state.findings = st.session_state.detector.analyze_all(plugin_results)
        st.session_state.evidence_loaded = True
        st.session_state.current_scenario = None
        st.session_state.analysis_complete = True

        findings_text = "\n".join(
            f"- [{f.risk_level.upper()}] {f.title}: {f.description}"
            for f in st.session_state.findings[:20]
        )
        if not findings_text:
            findings_text = "No detections were produced by the current plugin output."

        st.session_state.ai_engine.set_context(findings_text, f"Evidence: {evidence.filename}")

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


def render_home():
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
