"""VolatileAI — Home / Evidence Loader page."""

import streamlit as st
from ui.components.metrics import page_header, info_banner, stat_card
from core.volatility_engine import VolatilityEngine, PluginResult


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


def _load_demo_scenario(scenario_id: str, scenario: dict):
    plugin_data = st.session_state.scenario_loader.get_plugin_data(scenario_id)
    plugin_results = {}
    for plugin_name, data in plugin_data.items():
        plugin_results[plugin_name] = PluginResult(
            plugin_name=plugin_name, success=True, data=data, row_count=len(data)
        )
    st.session_state.plugin_results = plugin_results
    st.session_state.findings = st.session_state.detector.analyze_all(plugin_results)
    st.session_state.evidence_loaded = True
    st.session_state.current_scenario = scenario_id
    st.session_state.analysis_complete = True

    findings_text = "\n".join(
        f"- [{f.risk_level.upper()}] {f.title}: {f.description}"
        for f in st.session_state.findings[:20]
    )
    st.session_state.ai_engine.set_context(
        findings_text, f"Scenario: {scenario['name']}"
    )


def _render_evidence_loader():
    st.markdown(
        "<h3 style='color:#f1f5f9;font-weight:700;margin-bottom:0.4rem'>"
        "📂 Load Evidence File</h3>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color:#64748b;font-size:0.85rem;margin-bottom:1rem'>"
        "Load a real dump to run plugins and generate findings automatically.</p>",
        unsafe_allow_html=True,
    )

    file_path = st.text_input(
        "Evidence file path",
        placeholder="/path/to/memory.raw",
        label_visibility="collapsed",
    )

    if st.button("Validate & Load", type="primary", use_container_width=True):
        if not file_path or not file_path.strip():
            st.warning("Please enter a file path first.")
            return

        with st.spinner("Validating evidence file…"):
            evidence = st.session_state.vol_engine.validate_evidence(file_path.strip())

        if not evidence.is_valid:
            st.error(f"Invalid evidence file: **{evidence.filename}** — "
                     f"format `{evidence.format}` is not supported or file not found.")
            return

        st.markdown(
            f"""
            <div style='background:#0f172a;border:1px solid #1e293b;border-radius:12px;
                padding:1rem 1.2rem;margin-top:0.8rem'>
                <div style='font-weight:700;color:#38bdf8;margin-bottom:8px;font-size:0.95rem'>
                    Evidence Details
                </div>
                <table style='width:100%;color:#e2e8f0;font-size:0.85rem'>
                    <tr><td style='color:#64748b;padding:3px 0'>Filename</td>
                        <td style='text-align:right'>{evidence.filename}</td></tr>
                    <tr><td style='color:#64748b;padding:3px 0'>Size</td>
                        <td style='text-align:right'>{evidence.size_human}</td></tr>
                    <tr><td style='color:#64748b;padding:3px 0'>Format</td>
                        <td style='text-align:right'><code>{evidence.format}</code></td></tr>
                    <tr><td style='color:#64748b;padding:3px 0'>MD5</td>
                        <td style='text-align:right;font-family:monospace;font-size:0.75rem'>
                            {evidence.md5}</td></tr>
                    <tr><td style='color:#64748b;padding:3px 0'>SHA-256</td>
                        <td style='text-align:right;font-family:monospace;font-size:0.75rem'>
                            {evidence.sha256}</td></tr>
                </table>
            </div>""",
            unsafe_allow_html=True,
        )

        with st.spinner("Running Volatility plugins — this may take a few minutes…"):
            plugin_results = st.session_state.vol_engine.run_all_plugins(file_path.strip())

        st.session_state.plugin_results = plugin_results
        st.session_state.findings = st.session_state.detector.analyze_all(plugin_results)
        st.session_state.evidence_loaded = True
        st.session_state.current_scenario = None
        st.session_state.analysis_complete = True

        findings_text = "\n".join(
            f"- [{f.risk_level.upper()}] {f.title}: {f.description}"
            for f in st.session_state.findings[:20]
        )
        st.session_state.ai_engine.set_context(findings_text, f"Evidence: {evidence.filename}")

        info_banner("Evidence loaded and analysis complete! Head to the Dashboard to review findings.", "success")


def _render_demo_scenarios():
    st.markdown(
        "<h3 style='color:#f1f5f9;font-weight:700;margin-bottom:0.4rem'>"
        "🧪 Demo Scenarios</h3>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color:#64748b;font-size:0.85rem;margin-bottom:1rem'>"
        "Use curated scenarios if you want an instant walkthrough without a live dump.</p>",
        unsafe_allow_html=True,
    )

    scenarios = st.session_state.scenario_loader.list_scenarios()

    if not scenarios:
        st.info("No demo scenarios found. Add scenario JSON files to the demo directory.")
        return

    for scenario in scenarios:
        sid = scenario["id"]
        st.markdown(
            f"""
            <div style='background:#0f172a;border:1px solid #1e293b;border-radius:12px;
                padding:0.9rem 1.1rem;margin-bottom:0.7rem;
                box-shadow:0 2px 8px rgba(0,0,0,0.18)'>
                <div style='font-weight:700;color:#f1f5f9;font-size:0.95rem'>
                    {scenario['name']}
                </div>
                <div style='color:#94a3b8;font-size:0.82rem;margin-top:4px;line-height:1.5'>
                    {scenario.get('description', 'No description available.')}
                </div>
                <div style='margin-top:6px'>
                    <span style='background:#1e293b;color:#818cf8;padding:2px 8px;
                        border-radius:4px;font-size:0.7rem;font-family:monospace'>
                        {scenario.get('os', 'windows').upper()}
                    </span>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )
        if st.button(
            f"Load Scenario",
            key=f"load_{sid}",
            use_container_width=True,
        ):
            with st.spinner(f"Loading **{scenario['name']}**…"):
                _load_demo_scenario(sid, scenario)
            info_banner(
                f"Scenario \"{scenario['name']}\" loaded with "
                f"{len(st.session_state.findings)} findings. Go to the Dashboard to explore!",
                "success",
            )


def render_home():
    _render_hero()

    if st.session_state.get("evidence_loaded"):
        info_banner(
            "Evidence is loaded and ready. Navigate to the Dashboard to explore findings.",
            "success",
        )
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)

    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        _render_evidence_loader()

    with col_right:
        _render_demo_scenarios()
