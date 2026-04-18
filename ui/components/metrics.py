"""Reusable UI metric and badge components."""

import streamlit as st


def page_header(title: str, subtitle: str = "", icon: str = ""):
    icon_html = '<span style="font-size:1.4em">' + icon + '</span> ' if icon else ''
    header = icon_html + "<span style='font-size:1.8rem;font-weight:800;color:#f1f5f9'>" + title + "</span>"
    st.markdown("<div style='padding:0.5rem 0 0.2rem 0'>" + header + "</div>", unsafe_allow_html=True)
    if subtitle:
        st.markdown("<p style='color:#94a3b8;margin-top:0;font-size:0.95rem'>" + subtitle + "</p>", unsafe_allow_html=True)


def risk_badge(level: str, large: bool = False):
    colors = {
        "critical": ("#ef4444", "rgba(239,68,68,0.12)"),
        "high": ("#f97316", "rgba(249,115,22,0.12)"),
        "medium": ("#eab308", "rgba(234,179,8,0.12)"),
        "low": ("#22c55e", "rgba(34,197,94,0.12)"),
    }
    color, bg = colors.get(level.lower(), ("#94a3b8", "rgba(148,163,184,0.1)"))
    size = "1.1rem" if large else "0.8rem"
    pad = "6px 16px" if large else "3px 10px"
    dot = "⬤ " if large else ""
    html = (
        "<span style='background:" + bg + ";color:" + color + ";padding:" + pad + ";"
        "border-radius:20px;font-weight:700;font-size:" + size + ";"
        "border:1px solid " + color + "33'>"
        + dot + level.upper() + "</span>"
    )
    st.markdown(html, unsafe_allow_html=True)


def stat_card(label: str, value, color: str = "#38bdf8", icon: str = ""):
    icon_str = icon + " " if icon else ""
    html = (
        "<div style='background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);"
        "border:1px solid rgba(56,189,248,0.1);border-radius:14px;"
        "padding:1rem 1.2rem;text-align:center;"
        "box-shadow:0 4px 20px rgba(0,0,0,0.2)'>"
        "<div style='font-size:0.75rem;color:#64748b;text-transform:uppercase;"
        "letter-spacing:0.08em;font-weight:600;margin-bottom:4px'>"
        + icon_str + str(label) +
        "</div>"
        "<div style='font-size:1.8rem;font-weight:800;color:" + color + "'>"
        + str(value) +
        "</div></div>"
    )
    st.markdown(html, unsafe_allow_html=True)


def finding_card(title: str, description: str, risk_score: float,
                 category: str, techniques: list, evidence_id: str = "", triage_status: str = ""):
    risk_level = "critical" if risk_score >= 8 else "high" if risk_score >= 6 else "medium" if risk_score >= 4 else "low"
    color_map = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
    color = color_map[risk_level]
    cat_icons = {"process": "PROC", "network": "NET", "injection": "INJ", "dll": "DLL", "persistence": "PERS", "credential": "CRED"}
    icon = cat_icons.get(category, "OBS")

    techs_parts = []
    for t in techniques[:5]:
        techs_parts.append(
            "<span style='background:#1e293b;color:#38bdf8;padding:2px 8px;"
            "border-radius:4px;font-size:0.7rem;font-family:monospace;'>" + str(t) + "</span>"
        )
    techs_html = " ".join(techs_parts)

    evidence_html = ""
    if evidence_id:
        evidence_html = "<div style='color:#475569;font-size:0.7rem;margin-top:4px'>" + evidence_id + "</div>"

    score_str = "{:.1f}".format(risk_score)
    description = str(description or "")
    max_desc_len = 280
    if len(description) > max_desc_len:
        cutoff = description.rfind(" ", 0, max_desc_len)
        if cutoff <= 0:
            cutoff = max_desc_len
        desc_trunc = description[:cutoff].rstrip() + "..."
    else:
        desc_trunc = description

    status_label = ""
    status_color = ""
    if triage_status == "review":
        status_label = "HUMAN REVIEW REQUIRED"
        status_color = "#eab308"
    elif triage_status == "informational":
        status_label = "INFORMATIONAL"
        status_color = "#94a3b8"

    status_html = ""
    if status_label:
        status_html = (
            "<span style='background:" + status_color + "18;color:" + status_color + ";padding:2px 10px;"
            "border-radius:12px;font-size:0.72rem;font-weight:800;border:1px solid " + status_color + "33;"
            "white-space:nowrap;display:inline-flex;align-items:center;"
            "margin-left:8px'>" + status_label + "</span>"
        )

    html = (
        "<div style='background:#0f172a;border:1px solid " + color + "22;border-left:3px solid " + color + ";"
        "border-radius:10px;padding:0.8rem 1rem;margin-bottom:0.6rem;"
        "box-shadow:0 2px 10px rgba(0,0,0,0.15)'>"
        "<div style='display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:6px'>"
        "<div style='min-width:0;flex:1 1 auto;font-weight:700;color:#f1f5f9;font-size:0.95rem;line-height:1.25'>"
        "[" + icon + "] " + title + "</div>"
        "<span style='background:" + color + "18;color:" + color + ";padding:2px 10px;"
        "border-radius:12px;font-size:0.75rem;font-weight:700;border:1px solid " + color + "33'>"
        + score_str + " / 10</span>"
        "</div>"
        + status_html +
        "<div style='color:#94a3b8;font-size:0.85rem;margin-bottom:6px'>" + desc_trunc + "</div>"
        "<div style='display:flex;gap:4px;flex-wrap:wrap'>" + techs_html + "</div>"
        + evidence_html +
        "</div>"
    )
    st.markdown(html, unsafe_allow_html=True)


def info_banner(text: str, type_: str = "info"):
    color_map = {"info": "#38bdf8", "success": "#22c55e", "warning": "#eab308", "error": "#ef4444"}
    color = color_map.get(type_, "#38bdf8")
    icon_map = {"info": "INFO", "success": "OK", "warning": "WARN", "error": "ERR"}
    icon = icon_map.get(type_, "ℹ️")

    html = (
        "<div style='background:" + color + "08;border:1px solid " + color + "22;"
        "border-radius:10px;padding:0.7rem 1rem;margin:0.5rem 0;"
        "display:flex;align-items:center;gap:8px'>"
        "<span style='font-size:1.1rem'>" + icon + "</span>"
        "<span style='color:#e2e8f0;font-size:0.9rem'>" + text + "</span>"
        "</div>"
    )
    st.markdown(html, unsafe_allow_html=True)
