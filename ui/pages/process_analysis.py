"""Process Analysis page for VolatileAI forensics tool."""

import streamlit as st
import pandas as pd
from ui.components.metrics import page_header, info_banner, finding_card
from ui.components.charts import create_process_tree

SUSPICIOUS_PARENTS = {
    "cmd.exe": ["explorer.exe", "services.exe"],
    "powershell.exe": ["explorer.exe", "services.exe"],
    "svchost.exe": ["services.exe"],
    "lsass.exe": ["wininit.exe"],
    "csrss.exe": ["smss.exe"],
    "winlogon.exe": ["smss.exe"],
    "python.exe": ["services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"],
    "pythonw.exe": ["services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"],
    "python3.exe": ["services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"],
    "node.exe": ["services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"],
    "perl.exe": ["services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"],
    "ruby.exe": ["services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"],
}


def _has_suspicious_parent(name: str, ppid: int, pid_map: dict) -> bool:
    name_lower = name.lower()
    if name_lower not in SUSPICIOUS_PARENTS:
        return False

    if name_lower in {"csrss.exe", "winlogon.exe"}:
        parent = pid_map.get(ppid, {})
        parent_name = (parent.get("ImageFileName") or parent.get("Name") or parent.get("name") or "").lower()
        if not parent_name or parent_name == "unknown" or parent_name == "smss.exe":
            return False

    parent = pid_map.get(ppid, {})
    parent_name = (parent.get("ImageFileName") or parent.get("Name") or parent.get("name") or "").lower()
    return parent_name in [p.lower() for p in SUSPICIOUS_PARENTS[name_lower]]


def render_process_analysis():
    page_header("Process Analysis", subtitle="Inspect running processes, parent relationships, and suspicious behavior", icon="")

    if not st.session_state.get("evidence_loaded"):
        info_banner("Load a memory image from the sidebar to begin process analysis.")
        return

    plugin_results = st.session_state.plugin_results
    pslist = plugin_results.get("windows.pslist")
    cmdline_result = plugin_results.get("windows.cmdline")
    processes = pslist.data if pslist and pslist.success else []
    cmdlines = cmdline_result.data if cmdline_result and cmdline_result.success else []

    if not processes:
        info_banner("No process data available in the loaded evidence.", type_="warning")
        return

    pid_map = {}
    for p in processes:
        pid = p.get("PID") or p.get("pid")
        if pid is not None:
            pid_map[pid] = p

    cmdline_map = {}
    for c in cmdlines:
        cpid = c.get("PID") or c.get("pid")
        args = c.get("Args") or c.get("args") or c.get("CommandLine") or c.get("cmdline") or ""
        if cpid is not None:
            cmdline_map[cpid] = args

    process_findings = {
        f.artifact_id: f
        for f in st.session_state.get("findings", [])
        if f.category == "process"
    }
    risk_scores = {
        f.artifact_id: f.risk_score
        for f in st.session_state.get("findings", [])
        if f.category == "process"
    }

    tab_tree, tab_details = st.tabs(["Process Tree", "Process Details"])

    with tab_tree:
        for p in processes:
            pid = p.get("PID") or p.get("pid")
            p["_risk_score"] = risk_scores.get(f"PID:{pid}", 0)

        fig = create_process_tree(processes)
        st.plotly_chart(fig, width="stretch")

        st.markdown("""
        <div style='display:flex;gap:18px;justify-content:center;padding:0.4rem 0 0.6rem 0;flex-wrap:wrap'>
            <span style='color:#334155;font-size:0.8rem'>● Normal</span>
            <span style='color:#eab308;font-size:0.8rem'>● Medium Risk</span>
            <span style='color:#f97316;font-size:0.8rem'>● High Risk</span>
            <span style='color:#ef4444;font-size:0.8rem'>● Critical Risk</span>
        </div>""", unsafe_allow_html=True)

    with tab_details:
        rows = []
        for p in processes:
            pid = p.get("PID") or p.get("pid")
            ppid = p.get("PPID") or p.get("ppid")
            name = p.get("ImageFileName") or p.get("Name") or p.get("name") or ""
            create_time = p.get("CreateTime") or p.get("create_time") or ""
            threads = p.get("Threads") or p.get("threads") or ""
            rows.append({
                "PID": "" if pid is None else str(pid),
                "PPID": "" if ppid is None else str(ppid),
                "Name": str(name),
                "Create Time": str(create_time),
                "Threads": "" if threads is None else str(threads),
            })

        df = pd.DataFrame(rows)
        if not df.empty:

            def _highlight_suspicious(row):
                name = str(row.get("Name", ""))
                ppid_raw = str(row.get("PPID", "")).strip()
                ppid = int(ppid_raw) if ppid_raw.isdigit() else None
                if name.lower() in {"csrss.exe", "winlogon.exe", "wininit.exe"}:
                    return [""] * len(row)
                if ppid is not None and _has_suspicious_parent(name, ppid, pid_map):
                    return ["background-color: rgba(239,68,68,0.15); color: #fca5a5"] * len(row)
                pid = str(row.get("PID", "")).strip()
                if f"PID:{pid}" in risk_scores and risk_scores[f"PID:{pid}"] >= 6:
                    return ["background-color: rgba(249,115,22,0.12); color: #fdba74"] * len(row)
                return [""] * len(row)

            styled_df = df.style.apply(_highlight_suspicious, axis=1)
            st.dataframe(styled_df, width="stretch", height=min(400, 40 + len(df) * 35))

        st.markdown("---")
        st.markdown("<h4 style='color:#f1f5f9;font-weight:700'>Suspicious Processes</h4>", unsafe_allow_html=True)

        suspicious = [f for f in process_findings.values()]
        if not suspicious:
            info_banner("No suspicious processes detected.", type_="success")
        else:
            for finding in sorted(suspicious, key=lambda f: f.risk_score, reverse=True):
                finding_card(
                    title=finding.title,
                    description=finding.description,
                    risk_score=finding.risk_score,
                    category=finding.category,
                    techniques=finding.mitre_techniques,
                    evidence_id=finding.artifact_id,
                    triage_status=getattr(finding, "triage_status", ""),
                )

                pid_str = finding.artifact_id.replace("PID:", "")
                try:
                    pid_int = int(pid_str)
                except (ValueError, TypeError):
                    pid_int = None

                if pid_int and pid_int in cmdline_map:
                    cmd = cmdline_map[pid_int]
                    st.markdown(f"""
                    <div style='background:#0f172a;border:1px solid #1e293b;border-radius:8px;
                        padding:0.5rem 0.8rem;margin:0 0 0.8rem 0;font-family:monospace;font-size:0.82rem;
                        color:#94a3b8;overflow-x:auto;white-space:pre-wrap'>
                        <span style='color:#64748b;font-weight:600'>CMD ▸ </span>{cmd}
                    </div>""", unsafe_allow_html=True)

        flagged_parents = []
        expected_session_init = []
        for p in processes:
            pid = p.get("PID") or p.get("pid")
            ppid = p.get("PPID") or p.get("ppid")
            name = p.get("ImageFileName") or p.get("Name") or p.get("name") or ""
            if name.lower() in {"csrss.exe", "winlogon.exe"} and (ppid is None or not _has_suspicious_parent(name, ppid, pid_map)):
                expected_session_init.append({
                    "pid": pid,
                    "name": name,
                    "ppid": ppid,
                })
                continue

            if ppid is not None and _has_suspicious_parent(name, ppid, pid_map):
                parent_info = pid_map.get(ppid, {})
                parent_name = parent_info.get("ImageFileName") or parent_info.get("Name") or parent_info.get("name") or "unknown"
                flagged_parents.append({
                    "pid": pid,
                    "name": name,
                    "ppid": ppid,
                    "parent_name": parent_name,
                })

        if flagged_parents:
            st.markdown("---")
            st.markdown("<h4 style='color:#f1f5f9;font-weight:700'>Unusual Parent-Child Relationships</h4>", unsafe_allow_html=True)
            for fp in flagged_parents:
                st.markdown(f"""
                <div style='background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.18);
                    border-left:3px solid #ef4444;border-radius:8px;padding:0.6rem 1rem;margin-bottom:0.5rem'>
                    <span style='color:#fca5a5;font-weight:700'>{fp['name']}</span>
                    <span style='color:#64748b'> (PID {fp['pid']})</span>
                    <span style='color:#94a3b8'> ← spawned by </span>
                    <span style='color:#fca5a5;font-weight:700'>{fp['parent_name']}</span>
                    <span style='color:#64748b'> (PID {fp['ppid']})</span>
                    <span style='color:#ef4444;margin-left:8px;font-size:0.75rem'>Unexpected parent</span>
                </div>""", unsafe_allow_html=True)

        if expected_session_init:
            st.markdown("---")
            info_banner(
                "csrss.exe and winlogon.exe entries with a missing or self-terminated smss.exe parent are expected during Windows session initialization.",
                type_="info",
            )
