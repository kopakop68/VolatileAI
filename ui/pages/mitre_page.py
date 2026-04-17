"""MITRE ATT&CK mapping page for VolatileAI."""

import streamlit as st
import pandas as pd
from ui.components.metrics import page_header, info_banner, stat_card
from ui.components.charts import create_mitre_heatmap


def render_mitre():
    page_header("MITRE ATT&CK Mapping", icon="")

    if "findings" not in st.session_state or not st.session_state.findings:
        info_banner("Load evidence first to view MITRE ATT&CK mappings.", type_="warning")
        return

    mitre_mapper = st.session_state.mitre_mapper
    findings = st.session_state.findings
    tactic_data = mitre_mapper.get_tactic_heatmap_data(findings)
    detected_techniques = mitre_mapper.get_detected_techniques(findings)

    total_techniques = len(detected_techniques)
    tactics_covered = len([t for t, techs in tactic_data.items() if techs])
    highest_severity_tech = max(detected_techniques, key=lambda t: t.get("max_severity", 0), default=None)
    highest_label = highest_severity_tech.get("name", "N/A") if highest_severity_tech else "N/A"

    c1, c2, c3 = st.columns(3)
    with c1:
        stat_card("Total Techniques Detected", total_techniques, color="#ef4444")
    with c2:
        stat_card("Tactics Covered", tactics_covered, color="#f97316")
    with c3:
        stat_card("Highest Severity Technique", highest_label, color="#eab308")

    st.markdown("")

    fig = create_mitre_heatmap(tactic_data)
    st.plotly_chart(fig, width="stretch", key="mitre_heatmap")

    st.markdown("---")
    st.markdown("### Detected Techniques")

    if detected_techniques:
        rows = []
        for tech in detected_techniques:
            severity = tech.get("max_severity", 0)
            if severity >= 8:
                sev_label = "Critical"
            elif severity >= 6:
                sev_label = "High"
            elif severity >= 4:
                sev_label = "Medium"
            else:
                sev_label = "Low"
            rows.append({
                "Technique ID": tech.get("technique_id", ""),
                "Name": tech.get("name", ""),
                "Tactic": tech.get("tactic", ""),
                "Finding Count": tech.get("finding_count", 0),
                "Max Severity": sev_label,
                "Description": tech.get("description", "")[:120],
            })

        df = pd.DataFrame(rows)

        def _color_severity(val):
            colors = {
                "Critical": "color: #ef4444; font-weight: 700",
                "High": "color: #f97316; font-weight: 700",
                "Medium": "color: #eab308; font-weight: 700",
                "Low": "color: #22c55e; font-weight: 700",
            }
            return colors.get(val, "")

        styled = df.style.map(_color_severity, subset=["Max Severity"])
        st.dataframe(styled, width="stretch", hide_index=True)
    else:
        info_banner("No MITRE techniques detected in current findings.", type_="info")
        return

    st.markdown("---")
    st.markdown("### Technique Details")

    for tech in detected_techniques:
        tech_id = tech.get("technique_id", "Unknown")
        name = tech.get("name", "Unknown")
        severity = tech.get("max_severity", 0)

        if severity >= 8:
            badge = "Critical"
        elif severity >= 6:
            badge = "High"
        elif severity >= 4:
            badge = "Medium"
        else:
            badge = "Low"

        with st.expander(f"{tech_id} — {name}  |  {badge}"):
            st.markdown(f"**Description:** {tech.get('description', 'No description available.')}")

            guidance = tech.get("detection_guidance", "")
            if guidance:
                st.markdown(f"**Detection Guidance:** {guidance}")

            mitre_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
            st.markdown(f"[View on MITRE ATT&CK]({mitre_url})")

            associated = tech.get("findings", [])
            if associated:
                st.markdown("**Associated Findings:**")
                for finding in associated:
                    title = finding if isinstance(finding, str) else finding.get("title", str(finding))
                    st.markdown(f"- {title}")
