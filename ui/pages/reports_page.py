"""Report Generator page for VolatileAI forensics tool."""

import streamlit as st
from ui.components.metrics import page_header, info_banner, stat_card


REPORT_TYPES = {
    "Executive Summary Report": {
        "icon": "",
        "description": "High-level overview suitable for management — key findings, risk posture, and recommended actions.",
    },
    "Technical Analysis Report": {
        "icon": "",
        "description": "Deep-dive technical report with process trees, network artifacts, injection evidence, and full IOC listing.",
    },
    "IOC Report": {
        "icon": "",
        "description": "Focused list of indicators of compromise — IPs, domains, hashes, and suspicious artifacts for threat feeds.",
    },
    "MITRE ATT&CK Report": {
        "icon": "",
        "description": "Findings mapped to the MITRE ATT&CK framework with technique IDs, tactics, and detection coverage.",
    },
}


def _build_preview(report_type: str, findings: list) -> str:
    critical = [f for f in findings if f.risk_score >= 8]
    high = [f for f in findings if 6 <= f.risk_score < 8]
    medium = [f for f in findings if 4 <= f.risk_score < 6]

    lines = [f"**Report Type:** {report_type}", ""]
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append(f"- Critical: {len(critical)}")
    lines.append(f"- High: {len(high)}")
    lines.append(f"- Medium: {len(medium)}")
    lines.append("")

    if critical:
        lines.append("**Top Critical Findings:**")
        for f in critical[:5]:
            lines.append(f"- {f.title} (score {f.risk_score:.1f})")
        lines.append("")

    techniques = set()
    for f in findings:
        for t in f.mitre_techniques:
            techniques.add(t)
    if techniques:
        lines.append(f"**MITRE Techniques Covered:** {len(techniques)}")
        lines.append(", ".join(sorted(techniques)[:10]))
        if len(techniques) > 10:
            lines.append(f"_…and {len(techniques) - 10} more_")

    return "\n".join(lines)


def render_reports():
    page_header("Report Generator", subtitle="Generate professional forensic reports from your analysis", icon="")

    if not st.session_state.get("evidence_loaded"):
        info_banner("Load a memory image from the Home page before generating reports.")
        return

    findings = st.session_state.get("findings", [])

    c1, c2, c3 = st.columns(3)
    with c1:
        stat_card("Total Findings", len(findings), color="#38bdf8")
    with c2:
        critical_count = sum(1 for f in findings if f.risk_score >= 8)
        stat_card("Critical", critical_count, color="#ef4444")
    with c3:
        categories = len({f.category for f in findings})
        stat_card("Categories", categories, color="#818cf8")

    st.markdown("<div style='height:1.2rem'></div>", unsafe_allow_html=True)

    col_config, col_preview = st.columns([1, 1], gap="large")

    with col_config:
        st.markdown(
            "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.6rem'>Report Configuration</h4>",
            unsafe_allow_html=True,
        )

        report_type = st.selectbox(
            "Report Type",
            list(REPORT_TYPES.keys()),
            format_func=lambda x: x,
        )

        rt_info = REPORT_TYPES[report_type]
        st.markdown(
            f"<div style='background:#0f172a;border:1px solid #1e293b;border-radius:8px;"
            f"padding:0.6rem 1rem;margin-bottom:1rem;color:#94a3b8;font-size:0.85rem'>"
            f"{rt_info['description']}</div>",
            unsafe_allow_html=True,
        )

        st.markdown(
            "<div style='border-bottom:1px solid #1e293b;margin:0.5rem 0 1rem 0'></div>",
            unsafe_allow_html=True,
        )

        org_name = st.text_input("Organization Name", placeholder="Acme Corporation")
        analyst_name = st.text_input("Analyst Name", placeholder="Jane Smith")
        case_number = st.text_input("Case Number", placeholder="CASE-2026-0001")

        st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

        if st.button("Generate Report", type="primary", width="stretch"):
            if not case_number.strip():
                st.warning("Please provide a case number.")
            else:
                with st.spinner("Generating report — this may take a moment…"):
                    try:
                        from reports.report_generator import ReportGenerator

                        generator = ReportGenerator()
                        pdf_bytes = generator.generate(
                            report_type=report_type,
                            findings=st.session_state.findings,
                            plugin_results=st.session_state.plugin_results,
                            evidence_info=st.session_state.evidence_info,
                            org_name=org_name,
                            analyst_name=analyst_name,
                            case_number=case_number,
                            scenario_name="Real Evidence",
                            ai_engine=st.session_state.ai_engine,
                            scenario_id=st.session_state.current_scenario or "",
                        )
                        st.session_state["_last_pdf"] = pdf_bytes
                        st.session_state["_last_case"] = case_number
                        info_banner("Report generated successfully!", type_="success")
                    except Exception as e:
                        st.error(f"Report generation failed: {e}")

        if st.session_state.get("_last_pdf"):
            st.download_button(
                "Download PDF",
                data=st.session_state["_last_pdf"],
                file_name=f"volatileai_report_{st.session_state.get('_last_case', 'report')}.pdf",
                mime="application/pdf",
                width="stretch",
            )

    with col_preview:
        st.markdown(
            "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.6rem'>Report Preview</h4>",
            unsafe_allow_html=True,
        )

        preview = _build_preview(report_type, findings)
        st.markdown(
            f"<div style='background:#0f172a;border:1px solid #1e293b;border-radius:10px;"
            f"padding:1.2rem 1.4rem;color:#e2e8f0;font-size:0.88rem;line-height:1.7;"
            f"min-height:300px'>{_md_to_html(preview)}</div>",
            unsafe_allow_html=True,
        )

        st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

        scenario_id = st.session_state.get("current_scenario", "") or ""
        with st.expander("AI Summary Preview"):
            ai_summary = st.session_state.ai_engine.get_auto_analysis(scenario_id)
            st.markdown(ai_summary)


def _md_to_html(md: str) -> str:
    import re
    html = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    html = re.sub(r"\*\*(.+?)\*\*", r"<strong style='color:#38bdf8'>\1</strong>", html)
    html = re.sub(r"_(.+?)_", r"<em>\1</em>", html)
    html = html.replace("\n", "<br>")
    return html
