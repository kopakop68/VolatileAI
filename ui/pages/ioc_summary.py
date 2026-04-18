"""IOC Summary page for VolatileAI forensics tool."""

import streamlit as st
import pandas as pd
from ui.components.metrics import page_header, info_banner, stat_card


def render_ioc_summary():
    page_header("IOC Summary", subtitle="Indicators of Compromise extracted from memory analysis", icon="")

    if not st.session_state.get("evidence_loaded"):
        info_banner("Load a memory image from the Home page to view IOC summary.")
        return

    findings = st.session_state.findings
    suspicious_ips = set()
    suspicious_processes = set()
    review_processes = set()
    suspicious_ports = set()
    suspicious_services = set()
    mitre_techniques = set()

    ip_context = {}
    process_scores = {}

    for f in findings:
        if f.category == "network":
            evidence = f.evidence
            ip = str(evidence.get("ForeignAddr") or evidence.get("foreign_addr") or evidence.get("ip", ""))
            port = str(evidence.get("ForeignPort") or evidence.get("foreign_port") or "")
            if ip and ip not in ("0.0.0.0", "::", "*", "-", "127.0.0.1"):
                suspicious_ips.add(ip)
                ip_context[ip] = {
                    "finding": f.title,
                    "risk_score": f.risk_score,
                    "risk_level": f.risk_level,
                    "description": f.description,
                }
            if port and port != "0":
                suspicious_ports.add(port)
        elif f.category in ("process", "injection"):
            if getattr(f, "requires_manual_review", False):
                review_processes.add(f.title)
            else:
                suspicious_processes.add(f.title)
                process_scores[f.title] = f.risk_score
        elif f.category == "persistence":
            suspicious_services.add(f.title)
        for t in f.mitre_techniques:
            mitre_techniques.add(t)

    total_iocs = len(suspicious_ips) + len(suspicious_processes) + len(suspicious_ports) + len(suspicious_services)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        stat_card("Total IOCs", total_iocs, color="#c084fc")
    with c2:
        stat_card("Suspicious IPs", len(suspicious_ips), color="#ef4444")
    with c3:
        stat_card("Confirmed Processes", len(suspicious_processes), color="#f97316")
    with c4:
        stat_card("MITRE Techniques", len(mitre_techniques), color="#38bdf8")

    st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

    tab_ips, tab_procs, tab_ports, tab_svcs, tab_mitre = st.tabs([
        "IP Addresses",
        "Processes",
        "Network Ports",
        "Services",
        "MITRE Techniques",
    ])

    with tab_ips:
        if suspicious_ips:
            rows = []
            for ip in sorted(suspicious_ips):
                ctx = ip_context.get(ip, {})
                rows.append({
                    "IP Address": ip,
                    "Finding": ctx.get("finding", "—"),
                    "Risk Score": ctx.get("risk_score", 0),
                    "Risk Level": ctx.get("risk_level", "—").upper(),
                    "Context": ctx.get("description", "—")[:120],
                })
            df = pd.DataFrame(rows)

            def _color_risk(val):
                colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
                c = colors.get(val, "#94a3b8")
                return f"color: {c}; font-weight: 700"

            styled = df.style.map(_color_risk, subset=["Risk Level"])
            st.dataframe(styled, width="stretch", hide_index=True)
        else:
            info_banner("No suspicious external IP addresses detected.", type_="success")

    with tab_procs:
        if suspicious_processes:
            rows = []
            for proc in sorted(suspicious_processes):
                score = process_scores.get(proc, 0)
                level = "CRITICAL" if score >= 8 else "HIGH" if score >= 6 else "MEDIUM" if score >= 4 else "LOW"
                rows.append({"Process": proc, "Risk Score": score, "Risk Level": level})
            df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False)

            def _color_risk(val):
                colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
                c = colors.get(val, "#94a3b8")
                return f"color: {c}; font-weight: 700"

            styled = df.style.map(_color_risk, subset=["Risk Level"])
            st.dataframe(styled, width="stretch", hide_index=True)
        else:
            info_banner("No suspicious processes detected.", type_="success")

    if review_processes:
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        info_banner(
            f"{len(review_processes)} process/injection finding(s) are marked for human review and excluded from the confirmed IOC total.",
            type_="warning",
        )

    with tab_ports:
        if suspicious_ports:
            for port in sorted(suspicious_ports, key=lambda p: int(p) if p.isdigit() else 0):
                st.markdown(
                    f"<div style='background:#0f172a;border:1px solid #1e293b;border-left:3px solid #f97316;"
                    f"border-radius:8px;padding:0.5rem 1rem;margin-bottom:0.4rem;"
                    f"font-family:monospace;font-size:0.9rem;color:#fdba74'>"
                    f"Port <span style='font-weight:700;color:#f97316'>{port}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            info_banner("No suspicious network ports detected.", type_="success")

    with tab_svcs:
        if suspicious_services:
            for svc in sorted(suspicious_services):
                st.markdown(
                    f"<div style='background:#0f172a;border:1px solid #1e293b;border-left:3px solid #818cf8;"
                    f"border-radius:8px;padding:0.5rem 1rem;margin-bottom:0.4rem;"
                    f"color:#c4b5fd;font-size:0.9rem'>"
                    f"{svc}</div>",
                    unsafe_allow_html=True,
                )
        else:
            info_banner("No suspicious services detected.", type_="success")

    with tab_mitre:
        if mitre_techniques:
            cols = st.columns(3)
            for idx, tech in enumerate(sorted(mitre_techniques)):
                with cols[idx % 3]:
                    st.markdown(
                        f"<div style='background:#1e293b;color:#38bdf8;padding:6px 12px;"
                        f"border-radius:6px;font-family:monospace;font-size:0.85rem;"
                        f"margin-bottom:6px;text-align:center;border:1px solid #38bdf833'>"
                        f"{tech}</div>",
                        unsafe_allow_html=True,
                    )
        else:
            info_banner("No MITRE ATT&CK techniques mapped.", type_="info")

    st.markdown("---")
    st.markdown("<h4 style='color:#f1f5f9;font-weight:700'>Export IOCs</h4>", unsafe_allow_html=True)

    export_lines = []
    if suspicious_ips:
        export_lines.append("# Suspicious IP Addresses")
        export_lines.extend(sorted(suspicious_ips))
        export_lines.append("")
    if suspicious_processes:
        export_lines.append("# Suspicious Processes")
        export_lines.extend(sorted(suspicious_processes))
        export_lines.append("")
    if review_processes:
        export_lines.append("# Review Processes")
        export_lines.extend(sorted(review_processes))
        export_lines.append("")
    if suspicious_ports:
        export_lines.append("# Suspicious Ports")
        export_lines.extend(sorted(suspicious_ports, key=lambda p: int(p) if p.isdigit() else 0))
        export_lines.append("")
    if suspicious_services:
        export_lines.append("# Suspicious Services")
        export_lines.extend(sorted(suspicious_services))
        export_lines.append("")
    if mitre_techniques:
        export_lines.append("# MITRE ATT&CK Techniques")
        export_lines.extend(sorted(mitre_techniques))

    export_text = "\n".join(export_lines) if export_lines else "No IOCs extracted."
    st.text_area("IOC List (copy below)", value=export_text, height=220, label_visibility="collapsed")

    st.markdown("---")
    st.markdown("<h4 style='color:#f1f5f9;font-weight:700'>AI-Generated IOC Analysis</h4>", unsafe_allow_html=True)

    scenario_id = st.session_state.get("current_scenario", "") or ""
    ai_iocs = st.session_state.ai_engine.get_ioc_list(scenario_id)
    st.markdown(
        f"<div style='background:#0f172a;border:1px solid #1e293b;border-radius:10px;"
        f"padding:1rem 1.2rem;color:#e2e8f0;font-size:0.88rem;line-height:1.7;"
        f"white-space:pre-wrap'>{ai_iocs}</div>",
        unsafe_allow_html=True,
    )
