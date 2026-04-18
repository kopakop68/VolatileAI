"""Forensic Timeline page for VolatileAI."""

import textwrap

import streamlit as st
from datetime import datetime
from ui.components.metrics import page_header, info_banner, stat_card
from ui.components.charts import create_timeline


def _format_timestamp(value):
    if value is None:
        return "Timestamp unavailable"
    text = str(value).strip()
    if not text:
        return "Timestamp unavailable"

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    try:
        from dateutil import parser as date_parser  # type: ignore

        return date_parser.parse(text).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return text


def _extract_event_timestamp(finding):
    direct = getattr(finding, "timestamp", "") or ""
    if direct:
        return direct

    evidence = getattr(finding, "evidence", {}) or {}
    if not isinstance(evidence, dict):
        return ""

    candidate_keys = (
        "CreateTime",
        "create_time",
        "Created",
        "created",
        "Timestamp",
        "timestamp",
        "Time",
        "time",
        "LastModified",
        "last_modified",
        "InsertTime",
        "insert_time",
    )
    for key in candidate_keys:
        value = evidence.get(key)
        if value:
            return value

    return ""


def render_timeline():
    page_header("Forensic Timeline", icon="")

    if "findings" not in st.session_state or not st.session_state.findings:
        info_banner("Load evidence first to view the forensic timeline.", type_="warning")
        return

    scenario_id = st.session_state.get("current_scenario")
    if scenario_id:
        events = st.session_state.scenario_loader.get_timeline_events(
            scenario_id, st.session_state.findings
        )
    else:
        events = []
        for f in st.session_state.findings:
            timestamp = _extract_event_timestamp(f)
            events.append({
                "timestamp": timestamp,
                "category": f.category,
                "title": f.title,
                "risk_score": f.risk_score,
                "details": f.evidence,
            })
        events.sort(key=lambda e: e.get("timestamp", ""))

    if events and not any(str(e.get("timestamp", "")).strip() for e in events):
        info_banner(
            "The loaded findings do not contain usable timestamps, so the timeline can only show category order. If you want exact times, load a dump or scenario with CreateTime/Created fields.",
            "warning",
        )

    categories = sorted({e.get("category", "unknown") for e in events})
    total_events = len(events)
    high_risk_events = sum(1 for e in events if e.get("risk_score", 0) >= 7)
    avg_risk = sum(e.get("risk_score", 0) for e in events) / total_events if total_events else 0

    c1, c2, c3 = st.columns(3)
    with c1:
        stat_card("Total Events", total_events, color="#38bdf8")
    with c2:
        stat_card("High-Risk Events", high_risk_events, color="#ef4444")
    with c3:
        stat_card("Avg Risk Score", f"{avg_risk:.1f}", color="#eab308")

    st.markdown("")

    fig = create_timeline(events)
    st.plotly_chart(fig, width="stretch", key="timeline_chart")

    st.markdown("---")
    st.markdown("### Event Details")

    fc1, fc2 = st.columns([1, 2])
    with fc1:
        category_options = ["All"] + [c.capitalize() for c in categories]
        selected_cat = st.selectbox("Category Filter", category_options, key="tl_cat_filter")
    with fc2:
        min_risk = st.slider("Minimum Risk Score", 0.0, 10.0, 0.0, 0.5, key="tl_risk_filter")

    filtered = events
    if selected_cat != "All":
        filtered = [e for e in filtered if e.get("category", "").capitalize() == selected_cat]
    filtered = [e for e in filtered if e.get("risk_score", 0) >= min_risk]

    st.caption(f"Showing {len(filtered)} of {total_events} events")

    for evt in filtered:
        risk = evt.get("risk_score", 0)
        if risk >= 8:
            border_color = "#ef4444"
        elif risk >= 6:
            border_color = "#f97316"
        elif risk >= 4:
            border_color = "#eab308"
        else:
            border_color = "#334155"

        cat = evt.get("category", "unknown")
        cat_icons = {
            "process": "PROC", "network": "NET", "injection": "INJ",
            "dll": "DLL", "persistence": "PERS", "credential": "CRED",
            "service": "SVC",
        }
        icon = cat_icons.get(cat, "OBS")

        timestamp = _format_timestamp(evt.get("timestamp", ""))
        title = evt.get("title", "Untitled Event")

        st.markdown(f"""
        <div style='background:#0f172a;border:1px solid {border_color}22;
            border-left:3px solid {border_color};border-radius:10px;
            padding:0.7rem 1rem;margin-bottom:0.5rem;
            box-shadow:0 2px 10px rgba(0,0,0,0.15)'>
            <div style='display:flex;justify-content:space-between;align-items:center'>
                <div>
                    <span style='color:#64748b;font-size:0.75rem;font-family:monospace'>
                        {timestamp}
                    </span>
                    <span style='background:{border_color}18;color:{border_color};
                        padding:2px 8px;border-radius:8px;font-size:0.7rem;
                        font-weight:600;margin-left:8px;border:1px solid {border_color}33'>
                        {icon} {cat.upper()}
                    </span>
                </div>
                <span style='color:{border_color};font-weight:700;font-size:0.85rem'>
                    {risk:.1f}
                </span>
            </div>
            <div style='color:#f1f5f9;font-weight:600;font-size:0.9rem;margin-top:4px'>
                {title}
            </div>
        </div>""", unsafe_allow_html=True)

        details = evt.get("details")
        if details:
            detail_label = textwrap.shorten(str(title), width=54, placeholder="…")
            with st.expander(f"Details — {detail_label}", expanded=False):
                if isinstance(details, dict):
                    for k, v in details.items():
                        st.markdown(f"**{k}:** `{v}`")
                elif isinstance(details, list):
                    for item in details:
                        st.markdown(f"- {item}")
                else:
                    st.code(str(details))
