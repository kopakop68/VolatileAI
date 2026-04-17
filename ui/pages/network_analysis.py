"""Network Analysis page for VolatileAI forensics tool."""

import streamlit as st
import pandas as pd
from ui.components.metrics import page_header, info_banner, stat_card, finding_card
from ui.components.charts import create_network_graph


def render_network_analysis():
    page_header("Network Analysis", subtitle="Explore network connections, remote endpoints, and suspicious traffic", icon="")

    if not st.session_state.get("evidence_loaded"):
        info_banner("Load a memory image from the sidebar to begin network analysis.")
        return

    netscan = st.session_state.plugin_results.get("windows.netscan")
    connections = netscan.data if netscan and netscan.success else []

    if not connections:
        info_banner("No network connection data available in the loaded evidence.", type_="warning")
        return

    network_findings = [
        f for f in st.session_state.get("findings", [])
        if f.category == "network"
    ]

    remote_ips = set()
    unique_ports = set()
    for conn in connections:
        raddr = str(conn.get("ForeignAddr") or conn.get("foreign_addr") or "")
        rport = conn.get("ForeignPort") or conn.get("foreign_port")
        if raddr and raddr not in ("0.0.0.0", "::", "*", "-", "127.0.0.1"):
            remote_ips.add(raddr)
        if rport and str(rport) not in ("0", "*", "-"):
            unique_ports.add(rport)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        stat_card("Total Connections", len(connections), color="#38bdf8")
    with c2:
        stat_card("Unique Remote IPs", len(remote_ips), color="#818cf8")
    with c3:
        stat_card("Suspicious", len(network_findings), color="#ef4444")
    with c4:
        stat_card("Unique Ports", len(unique_ports), color="#f97316")

    st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

    tab_graph, tab_details = st.tabs(["Network Graph", "Connection Details"])

    with tab_graph:
        fig = create_network_graph(connections)
        st.plotly_chart(fig, width="stretch")

        st.markdown("""
        <div style='display:flex;gap:24px;justify-content:center;padding:0.4rem 0 0.6rem 0;flex-wrap:wrap'>
            <div style='display:flex;align-items:center;gap:6px'>
                <span style='display:inline-block;width:12px;height:12px;border-radius:50%;background:#38bdf8'></span>
                <span style='color:#94a3b8;font-size:0.82rem'>Local Address</span>
            </div>
            <div style='display:flex;align-items:center;gap:6px'>
                <span style='display:inline-block;width:12px;height:12px;border-radius:50%;background:#ef4444'></span>
                <span style='color:#94a3b8;font-size:0.82rem'>Remote Address</span>
            </div>
            <div style='display:flex;align-items:center;gap:6px'>
                <span style='display:inline-block;width:18px;height:2px;background:rgba(148,163,184,0.4)'></span>
                <span style='color:#94a3b8;font-size:0.82rem'>Connection</span>
            </div>
        </div>""", unsafe_allow_html=True)

    with tab_details:
        rows = []
        all_states = set()
        all_pids = set()
        for conn in connections:
            proto = conn.get("Proto") or conn.get("protocol") or ""
            local_addr = conn.get("LocalAddr") or conn.get("local_addr") or ""
            local_port = conn.get("LocalPort") or conn.get("local_port") or ""
            remote_addr = conn.get("ForeignAddr") or conn.get("foreign_addr") or ""
            remote_port = conn.get("ForeignPort") or conn.get("foreign_port") or ""
            state = conn.get("State") or conn.get("state") or ""
            pid = conn.get("PID") or conn.get("pid") or ""
            owner = conn.get("Owner") or conn.get("owner") or conn.get("ImageFileName") or ""

            if state:
                all_states.add(str(state))
            if pid:
                all_pids.add(str(pid))

            rows.append({
                "Protocol": str(proto),
                "Local Address": str(local_addr),
                "Local Port": "" if local_port is None else str(local_port),
                "Remote Address": str(remote_addr),
                "Remote Port": "" if remote_port is None else str(remote_port),
                "State": str(state),
                "PID": "" if pid is None else str(pid),
                "Owner": str(owner),
            })

        df = pd.DataFrame(rows)

        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            selected_states = st.multiselect(
                "Filter by State",
                sorted(all_states),
                default=[],
                key="net_state_filter",
            )
        with filter_col2:
            selected_pids = st.multiselect(
                "Filter by PID",
                sorted(all_pids, key=lambda x: int(x) if x.isdigit() else 0),
                default=[],
                key="net_pid_filter",
            )

        filtered_df = df.copy()
        if selected_states:
            filtered_df = filtered_df[filtered_df["State"].astype(str).isin(selected_states)]
        if selected_pids:
            filtered_df = filtered_df[filtered_df["PID"].astype(str).isin(selected_pids)]

        suspicious_remotes = {
            f.artifact_id for f in network_findings
        }

        def _highlight_conn(row):
            remote = str(row.get("Remote Address", ""))
            pid = str(row.get("PID", ""))
            if f"CONN:{remote}" in suspicious_remotes or f"PID:{pid}" in suspicious_remotes:
                return ["background-color: rgba(239,68,68,0.12); color: #fca5a5"] * len(row)
            state = str(row.get("State", "")).upper()
            if state == "ESTABLISHED":
                return ["background-color: rgba(56,189,248,0.06); color: #e2e8f0"] * len(row)
            return [""] * len(row)

        styled = filtered_df.style.apply(_highlight_conn, axis=1)
        st.dataframe(styled, width="stretch", height=min(500, 40 + len(filtered_df) * 35))

        st.markdown(
            f"<div style='color:#64748b;font-size:0.78rem;text-align:right;padding:2px 4px'>"
            f"Showing {len(filtered_df)} of {len(df)} connections</div>",
            unsafe_allow_html=True,
        )

        st.markdown("---")
        st.markdown("<h4 style='color:#f1f5f9;font-weight:700'>Suspicious Connections</h4>", unsafe_allow_html=True)

        if not network_findings:
            info_banner("No suspicious network activity detected.", type_="success")
        else:
            for finding in sorted(network_findings, key=lambda f: f.risk_score, reverse=True):
                finding_card(
                    title=finding.title,
                    description=finding.description,
                    risk_score=finding.risk_score,
                    category=finding.category,
                    techniques=finding.mitre_techniques,
                    evidence_id=finding.artifact_id,
                )
