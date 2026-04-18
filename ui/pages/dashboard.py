"""VolatileAI — Investigation Dashboard page."""

from html import escape

import streamlit as st
from ui.components.metrics import page_header, info_banner, stat_card, finding_card
from ui.components.charts import create_risk_donut, create_category_bar


def render_dashboard():
    page_header(
        "Investigation Dashboard",
        subtitle="Overview of anomalies, risk distribution, and critical findings",
        icon="",
    )

    if not st.session_state.get("evidence_loaded"):
        info_banner(
            "No evidence loaded yet. Go to the Home page and load an evidence file first.",
            "info",
        )
        return

    findings = st.session_state.get("findings", [])
    risk_summary = st.session_state.detector.get_risk_summary()
    review_findings = [f for f in findings if getattr(f, "triage_status", "") == "review"]
    critical_findings = [f for f in findings if getattr(f, "triage_status", "") != "review"]

    total_findings = len(findings)
    critical_count = risk_summary.get("critical", 0)
    all_techniques = set()
    for f in findings:
        all_techniques.update(f.mitre_techniques)
    unique_techniques = len(all_techniques)
    risk_score = sum(f.risk_score for f in findings) / total_findings if total_findings else 0

    # --- Top metrics ---
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        stat_card("Total Findings", total_findings, color="#38bdf8")
    with m2:
        stat_card("Critical", critical_count, color="#ef4444")
    with m3:
        stat_card("MITRE Techniques", unique_techniques, color="#818cf8")
    with m4:
        stat_card("Avg Risk Score", f"{risk_score:.1f}", color="#f97316")

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
        st.plotly_chart(fig_donut, width="stretch", config={"displayModeBar": False})

    with chart_right:
        st.markdown(
            "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.3rem'>"
            "Findings by Category</h4>",
            unsafe_allow_html=True,
        )
        findings_by_cat = st.session_state.detector.get_findings_by_category()
        category_counts = {cat: len(items) for cat, items in findings_by_cat.items()}
        fig_bar = create_category_bar(category_counts)
        st.plotly_chart(fig_bar, width="stretch", config={"displayModeBar": False})

    st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

    if review_findings:
        info_banner(
            f"{len(review_findings)} finding(s) need human review. These are not being treated as confirmed malicious activity.",
            "warning",
        )

    # --- Top critical findings ---
    st.markdown(
        "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.5rem'>"
        "Top Critical Findings</h4>",
        unsafe_allow_html=True,
    )

    top_findings = sorted(critical_findings, key=lambda f: f.risk_score, reverse=True)[:10]

    if not top_findings:
        if review_findings:
            info_banner("No confirmed malicious findings detected. Review items are listed below for analyst validation.", "info")
        else:
            info_banner("No findings detected in the loaded evidence.", "info")
        plugin_results = st.session_state.get("plugin_results", {})
        if plugin_results:
            succeeded = sum(1 for result in plugin_results.values() if result.success)
            non_empty = sum(1 for result in plugin_results.values() if result.success and result.row_count > 0)
            st.markdown(
                f"<div style='color:#94a3b8;font-size:0.82rem;margin-top:0.35rem'>"
                f"Plugin summary: {succeeded}/{len(plugin_results)} succeeded, {non_empty} returned data rows."
                f"</div>",
                unsafe_allow_html=True,
            )
            if succeeded == 0:
                info_banner(
                    "No plugin data was parsed. This is usually a Volatility/profile/runtime issue, not a UI issue.",
                    "warning",
                )
    else:
        for f in top_findings:
            finding_card(
                title=f.title,
                description=f.description,
                risk_score=f.risk_score,
                category=f.category,
                techniques=f.mitre_techniques,
                evidence_id=f.artifact_id,
                triage_status=getattr(f, "triage_status", ""),
            )

    if review_findings:
        st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)
        st.markdown(
            "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.5rem'>Human Review Required</h4>",
            unsafe_allow_html=True,
        )
        for f in sorted(review_findings, key=lambda f: f.risk_score, reverse=True):
            finding_card(
                title=f.title,
                description=f.description,
                risk_score=f.risk_score,
                category=f.category,
                techniques=f.mitre_techniques,
                evidence_id=f.artifact_id,
                triage_status=getattr(f, "triage_status", "review"),
            )

    st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

    # --- Priority actions ---
    st.markdown(
        "<h4 style='color:#f1f5f9;font-weight:700;margin-bottom:0.5rem'>"
        "Investigation Priorities</h4>",
        unsafe_allow_html=True,
    )

    top_three = sorted(critical_findings, key=lambda f: f.risk_score, reverse=True)[:3]
    if not top_three:
        if review_findings:
            info_banner("Only review items are present right now. Validate those first, then rerun analysis if needed.", "warning")
        else:
            info_banner("No findings yet. Load evidence to begin analysis.", "info")
        return

    actions = []
    for finding in top_three:
        if getattr(finding, "triage_status", "") == "review":
            action = (
                f"Review <strong>{escape(finding.title)}</strong> with human attention first "
                f"({finding.risk_score:.1f}/10) and confirm whether it is expected behavior or a true issue."
            )
            actions.append(action)
            continue
        action = (
            f"Review <strong>{escape(finding.title)}</strong> "
            f"({finding.risk_level.upper()}, {finding.risk_score:.1f}/10) and validate artifact "
            f"<code>{escape(finding.artifact_id)}</code>."
        )
        actions.append(action)

    actions.append("Open the <strong>AI Analyst</strong> page for guided narrative and remediation recommendations.")
    actions.append("Generate a <strong>Technical Analysis Report</strong> once critical findings are validated.")

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
