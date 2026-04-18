"""Plotly chart components for VolatileAI."""

from datetime import datetime

import plotly.graph_objects as go
import pandas as pd
from typing import Dict, List, Any

COLORS = {
    "primary": "#38bdf8", "secondary": "#818cf8", "success": "#22c55e",
    "warning": "#eab308", "danger": "#ef4444", "orange": "#f97316",
    "cyan": "#06b6d4", "pink": "#ec4899", "bg_dark": "#020617",
    "bg_card": "#0f172a", "border": "#1e293b", "text": "#e2e8f0",
    "text_muted": "#94a3b8",
}

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color=COLORS["text"], family="Inter, system-ui, sans-serif"),
    margin=dict(l=40, r=40, t=50, b=40),
)

RISK_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}


def _parse_timestamp(value: Any):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None

    candidate_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ]
    for fmt in candidate_formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue

    try:
        from dateutil import parser as date_parser  # type: ignore
        return date_parser.parse(text)
    except Exception:
        return None


def create_risk_donut(summary: Dict[str, int]) -> go.Figure:
    labels = list(summary.keys())
    values = list(summary.values())
    colors = [RISK_COLORS.get(l, "#94a3b8") for l in labels]

    fig = go.Figure(go.Pie(
        labels=[l.capitalize() for l in labels], values=values, hole=0.65,
        marker=dict(colors=colors, line=dict(color="#0f172a", width=2)),
        textinfo="label+value", textfont=dict(size=12, color="white"),
        hovertemplate="<b>%{label}</b>: %{value} findings<extra></extra>",
    ))
    fig.add_annotation(text=f"<b>{sum(values)}</b><br>Total", font=dict(size=20, color="#e2e8f0"), showarrow=False)
    layout = {**DARK_LAYOUT, "margin": dict(l=20, r=20, t=30, b=20)}
    fig.update_layout(**layout, showlegend=True, height=320,
        legend=dict(orientation="h", y=-0.1, x=0.5, xanchor="center", font=dict(size=11, color="#94a3b8")))
    return fig


def create_category_bar(findings_by_cat: Dict[str, int]) -> go.Figure:
    cats = list(findings_by_cat.keys())
    counts = list(findings_by_cat.values())
    cat_colors = {"process": "#38bdf8", "network": "#818cf8", "injection": "#ef4444",
                  "dll": "#f97316", "persistence": "#ec4899", "credential": "#eab308"}
    colors = [cat_colors.get(c, "#94a3b8") for c in cats]

    fig = go.Figure(go.Bar(
        x=[c.capitalize() for c in cats], y=counts, marker_color=colors,
        text=counts, textposition="auto", textfont=dict(size=13, color="white"),
    ))
    fig.update_layout(**DARK_LAYOUT, height=320, title=dict(text="Findings by Category", font=dict(size=15)),
        xaxis=dict(gridcolor="#1e293b"), yaxis=dict(gridcolor="#1e293b", title="Count"))
    return fig


def create_process_tree(processes: List[Dict]) -> go.Figure:
    """Create a visual process tree using treemap."""
    if not processes:
        return go.Figure()

    ids, labels, parents, colors, hover_texts = [], [], [], [], []
    pid_map = {}

    for p in processes:
        pid = p.get("PID") or p.get("pid")
        name = p.get("ImageFileName") or p.get("Name") or p.get("name") or "?"
        ppid = p.get("PPID") or p.get("ppid")
        pid_map[pid] = {"name": name, "ppid": ppid, "raw": p}

    root_id = "root"
    ids.append(root_id)
    labels.append("System")
    parents.append("")
    colors.append("#1e293b")
    hover_texts.append("Root")

    for pid, info in pid_map.items():
        node_id = f"pid_{pid}"
        ids.append(node_id)
        labels.append(f"{info['name']}<br>PID:{pid}")

        ppid_node = f"pid_{info['ppid']}" if info['ppid'] in pid_map else root_id
        parents.append(ppid_node)

        risk = info["raw"].get("_risk_score", 0)
        if risk >= 8:
            colors.append("#ef4444")
        elif risk >= 6:
            colors.append("#f97316")
        elif risk >= 4:
            colors.append("#eab308")
        else:
            colors.append("#334155")

        hover_texts.append(f"PID: {pid} | PPID: {info['ppid']} | {info['name']}")

    fig = go.Figure(go.Treemap(
        ids=ids, labels=labels, parents=parents,
        marker=dict(colors=colors, line=dict(color="#020617", width=2)),
        textfont=dict(size=11, color="white"),
        hovertext=hover_texts, hoverinfo="text",
    ))
    layout = {**DARK_LAYOUT, "margin": dict(l=5, r=5, t=40, b=5)}
    fig.update_layout(**layout, height=500, title=dict(text="Process Tree", font=dict(size=15)))
    return fig


def create_network_graph(connections: List[Dict]) -> go.Figure:
    """Create a network connection visualization."""
    if not connections:
        return go.Figure()

    def _is_loopback_or_local(addr: str) -> bool:
        normalized = str(addr).strip().lower()
        if normalized.startswith("[") and normalized.endswith("]"):
            normalized = normalized[1:-1]
        if "%" in normalized:
            normalized = normalized.split("%", 1)[0]
        return normalized in {"", "0.0.0.0", "::", "::1", "*", "-", "127.0.0.1", "localhost"}

    local_ips = set()
    remote_ips = set()
    edges = []
    node_types = {}

    for conn in connections:
        local = str(conn.get("LocalAddr") or conn.get("local_addr") or "")
        remote = str(conn.get("ForeignAddr") or conn.get("foreign_addr") or "")
        pid = conn.get("PID") or conn.get("pid") or ""
        port = conn.get("ForeignPort") or conn.get("foreign_port") or ""

        if local and _is_loopback_or_local(local):
            node_types[local] = "local"
        elif local:
            node_types.setdefault(local, "local")

        if remote and _is_loopback_or_local(remote):
            local_ips.add(remote)
            node_types[remote] = "local"
            continue

        if remote:
            local_ips.add(local)
            remote_ips.add(remote)
            edges.append((local, remote, pid, port))
            node_types.setdefault(remote, "remote")

    import networkx as nx
    G = nx.Graph()
    for lip in local_ips:
        G.add_node(lip, node_type=node_types.get(lip, "local"))
    for rip in remote_ips:
        G.add_node(rip, node_type=node_types.get(rip, "remote"))
    for l, r, pid, port in edges:
        G.add_edge(l, r, pid=pid, port=port)

    pos = nx.spring_layout(G, seed=42, k=2)

    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        if G.nodes[node].get("node_type") == "local":
            node_color.append("#38bdf8")
            node_size.append(20)
        else:
            node_color.append("#f97316")
            node_size.append(15)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
        line=dict(width=1, color="rgba(148,163,184,0.3)"), hoverinfo="none"))
    fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text",
        marker=dict(size=node_size, color=node_color, line=dict(width=1, color="#0f172a")),
        text=node_text, textposition="top center", textfont=dict(size=9, color="#94a3b8"),
        hovertemplate="<b>%{text}</b><extra></extra>"))

    layout = {**DARK_LAYOUT, "margin": dict(l=10, r=10, t=40, b=10)}
    fig.update_layout(**layout, height=450, showlegend=False,
        title=dict(text="Network Connections", font=dict(size=15)),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
    return fig


def create_timeline(events: List[Dict]) -> go.Figure:
    """Create an interactive forensic timeline."""
    if not events:
        return go.Figure()

    cat_colors = {"process": "#38bdf8", "network": "#818cf8", "injection": "#ef4444",
                  "dll": "#f97316", "persistence": "#ec4899", "service": "#06b6d4"}

    categories = sorted({str(e.get("category", "unknown")).lower() for e in events})
    cat_to_index = {cat: idx for idx, cat in enumerate(categories)}
    per_category_count: Dict[str, int] = {cat: 0 for cat in categories}
    point_offsets: Dict[tuple, int] = {}

    xs = []
    ys = []
    sizes = []
    colors = []
    hover_titles = []
    hover_times = []
    hover_risks = []
    hover_categories = []

    for evt in events:
        category = str(evt.get("category", "unknown")).lower()
        cat_idx = cat_to_index.get(category, 0)
        per_category_count[category] = per_category_count.get(category, 0) + 1

        risk = float(evt.get("risk_score", 0) or 0)
        size = max(8, min(26, 8 + risk * 1.8))

        parsed_ts = _parse_timestamp(evt.get("timestamp", ""))
        if parsed_ts:
            offset_key = (parsed_ts, category)
            offset_count = point_offsets.get(offset_key, 0)
            point_offsets[offset_key] = offset_count + 1
            ts_value = parsed_ts + pd.Timedelta(milliseconds=200 * offset_count)
        else:
            ts_value = evt.get("timestamp", "")

        xs.append(ts_value)
        ys.append(cat_idx)
        sizes.append(size)
        colors.append(cat_colors.get(category, "#94a3b8"))
        hover_titles.append(str(evt.get("title", "")))
        hover_times.append(parsed_ts.strftime("%Y-%m-%d %H:%M:%S") if parsed_ts else str(evt.get("timestamp", "")))
        hover_risks.append(risk)
        hover_categories.append(category.capitalize())

    fig = go.Figure(
        go.Scatter(
            x=xs,
            y=ys,
            mode="markers",
            marker=dict(
                size=sizes,
                color=colors,
                opacity=0.88,
                line=dict(width=1, color="#0f172a"),
            ),
            customdata=list(zip(hover_titles, hover_times, hover_risks, hover_categories)),
            hovertemplate="<b>%{customdata[0]}</b><br>Time: %{customdata[1]}<br>Category: %{customdata[3]}<br>Risk: %{customdata[2]:.1f}<extra></extra>",
            showlegend=False,
        )
    )

    fig.update_layout(
        **DARK_LAYOUT,
        height=max(380, 180 + len(categories) * 70),
        title=dict(text="Attack Timeline", font=dict(size=15)),
        xaxis=dict(title="Time", gridcolor="#1e293b", type="date", tickformat="%Y-%m-%d\n%H:%M"),
        yaxis=dict(
            title="Category",
            gridcolor="#1e293b",
            tickmode="array",
            tickvals=list(range(len(categories))),
            ticktext=[c.capitalize() for c in categories],
            zeroline=False,
        ),
        hovermode="closest",
    )
    return fig


def create_mitre_heatmap(tactic_data: Dict[str, List]) -> go.Figure:
    """Create MITRE ATT&CK tactic heatmap."""
    tactics = []
    techniques = []
    severities = []

    for tactic, tech_list in tactic_data.items():
        if tech_list:
            for t in tech_list:
                tactics.append(tactic)
                techniques.append(t["technique_name"])
                severities.append(t["max_severity"])

    if not tactics:
        fig = go.Figure()
        fig.add_annotation(text="No MITRE techniques detected", font=dict(size=16, color="#94a3b8"), showarrow=False)
        fig.update_layout(**DARK_LAYOUT, height=400)
        return fig

    fig = go.Figure(go.Scatter(
        x=tactics, y=techniques, mode="markers",
        marker=dict(
            size=[s * 5 for s in severities],
            color=severities,
            colorscale=[[0, "#22c55e"], [0.4, "#eab308"], [0.7, "#f97316"], [1, "#ef4444"]],
            showscale=True,
            colorbar=dict(title=dict(text="Severity", font=dict(color="#94a3b8")),
                          tickfont=dict(color="#64748b")),
            line=dict(width=1, color="#0f172a"),
        ),
        hovertemplate="<b>%{y}</b><br>Tactic: %{x}<br>Severity: %{marker.color:.1f}<extra></extra>",
    ))

    layout = {**DARK_LAYOUT, "margin": dict(l=280, r=30, t=50, b=40)}
    fig.update_layout(
        **layout,
        height=max(400, len(techniques) * 35),
        title=dict(text="MITRE ATT&CK Detection Map", font=dict(size=15)),
        xaxis=dict(tickangle=-45, gridcolor="#1e293b"),
        yaxis=dict(gridcolor="#1e293b"),
    )
    return fig
