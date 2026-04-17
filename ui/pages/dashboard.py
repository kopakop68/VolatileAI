"""VolatileAI — Investigation Dashboard page."""

import streamlit as st
from ui.components.metrics import page_header, info_banner, stat_card, finding_card
from ui.components.charts import create_risk_donut, create_category_bar


def render_dashboard():
    page_header(
        "Investigation Dashboard",
        subtitle="Overview of anomalies, risk distribution, and critical findings",
        icon="📊",
    )

    if not st.session_state.get("evidence_loaded"):
        info_banner(
            "No evidence loaded yet. Go to the Home page and load an evidence file or demo scenario first.",
            "info",
        )
        return

    findings = st.session_state.get("findings", [])
    risk_summary = st.session_state.detector.get_risk_summary()

    total_findings = len(findings)
    critical_count = risk_summary.get("critical", 0)
    all_techniques = set()
    for f in findings:
        all_techniques.update(f.mitre_techniques)
    unique_techniques = len(all_techniques)
    risk_score = max((f.risk_score for f in findings), default=0)

    # --- Top metrics ---
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        stat_card("Total Findings", total_findings, color="#38bdf8", icon="🔍")
    with m2:
        stat_card("Critical", critical_count, color="#ef4444", icon="🚨")
    with m3:
        stat_card("MITRE Techniques", unique_techniques, color="#818cf8", icon="🗺️")
    with m4:
        stat_card("Risk Score", f"{risk_score:.1f}", color="#f97316", icon="⚡")

    st.markdown("<div style='height:1.2rem'></div>", unsafe_allow_html=True)

    # --- Charts ---
    chart_left, chart_right = st.columns(2, gap="medium")

    with chart_left:
        st.markdown(
            "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.3rem'>"
            "Risk Distribution</h4>",
            unsafe_allow_html=True,
        )
        fig_donut = create_risk_donut(risk_summary)
        st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False})

    with chart_right:
        st.markdown(
            "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.3rem'>"
            "Findings by Category</h4>",
            unsafe_allow_html=True,
        )
        findings_by_cat = st.session_state.detector.get_findings_by_category()
        category_counts = {cat: len(items) for cat, items in findings_by_cat.items()}
        fig_bar = create_category_bar(category_counts)
        st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})

    st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

    # --- Top critical findings ---
    st.markdown(
        "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.5rem'>"
        "🔴 Top Critical Findings</h4>",
        unsafe_allow_html=True,
    )

    top_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:10]

    if not top_findings:
        info_banner("No findings detected in the loaded evidence.", "info")
    else:
        for f in top_findings:
            finding_card(
                title=f.title,
                description=f.description,
                risk_score=f.risk_score,
                category=f.category,
                techniques=f.mitre_techniques,
                evidence_id=f.artifact_id,
            )

    st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

    # --- Priority actions ---
    st.markdown(
        "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.5rem'>"
        "✅ Investigation Priorities</h4>",
        unsafe_allow_html=True,
    )

    top_three = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:3]
    if not top_three:
        info_banner("No findings yet. Load evidence or a demo scenario to begin analysis.", "info")
        return

    actions = []
    for finding in top_three:
        action = f"Review **{finding.title}** ({finding.risk_level.upper()}, {finding.risk_score:.1f}/10) and validate artifact `{finding.artifact_id}`."
        actions.append(action)

    actions.append("Open the **AI Analyst** page for guided narrative and remediation recommendations.")
    actions.append("Generate a **Technical Analysis Report** once critical findings are validated.")

    action_html = "".join(f"<li style='margin:0.45rem 0'>{item}</li>" for item in actions)

    st.markdown(
        f"""
        <div style='background:linear-gradient(135deg,#0b1220 0%,#12233f 100%);
            border:1px solid rgba(56,189,248,0.2);border-radius:14px;
            padding:1.2rem 1.4rem;box-shadow:0 4px 20px rgba(0,0,0,0.25)'>
            <div style='color:#cbd5e1;font-size:0.9rem;line-height:1.65'>
                <ul style='padding-left:1.1rem;margin:0'>
                    {action_html}
                </ul>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )
