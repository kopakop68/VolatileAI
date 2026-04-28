"""Tool-style documentation page for VolatileAI."""

import re
from html import escape
from pathlib import Path

import streamlit as st

from ui.components.metrics import info_banner, page_header


GUIDE_PAGES = {
    "quick-start": {
        "title": "Quick Start",
        "subtitle": "Get the app running and complete your first analysis.",
        "sections": [
            {
                "id": "prerequisites",
                "title": "Prerequisites",
                "content": """
- Linux/WSL environment with Python 3.10+.
- Access to a valid Windows memory dump file.
- Internet access only if you use cloud AI providers.
- Run inside project root: `/home/kopal/Major/VolatileAI`.
                """.strip(),
            },
            {
                "id": "install-and-run",
                "title": "Install and Run",
                "content": """
```bash
cd /home/kopal/Major/VolatileAI
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

Open: `http://localhost:8502`
                """.strip(),
            },
            {
                "id": "first-analysis",
                "title": "First Analysis Flow",
                "content": """
1. Go to **Home**.
2. Enter absolute memory dump path.
3. Choose a plugin profile.
4. Click **Validate & Load**.
5. Wait for plugin progress to reach 100%.
6. Open **Dashboard** for triage.
                """.strip(),
            },
            {
                "id": "navigation-map",
                "title": "Navigation Map",
                "content": """
- **Home**: Load evidence and start analysis.
- **Dashboard**: High-level risk and top findings.
- **Process / Network / MITRE / Timeline**: Deep-dive views.
- **AI Analyst**: Guided Q&A and narrative support.
- **IOC Summary / Reports**: Export-ready outputs.
                """.strip(),
            },
        ],
    },
    "evidence-workflow": {
        "title": "Evidence Workflow",
        "subtitle": "How to load dumps correctly and tune plugin execution.",
        "sections": [
            {
                "id": "input-requirements",
                "title": "Input Requirements",
                "content": """
- Use a real memory image path (not a folder).
- Prefer local disk paths for faster reads.
- Large files may take longer while hashes are computed.
                """.strip(),
            },
            {
                "id": "plugin-profiles",
                "title": "Plugin Profiles",
                "content": """
- **Quick Triage**: Fast baseline coverage.
- **Full Analysis**: Full plugin set (slowest).
- **Network Focus**: Network-centric triage.
- **Injection Focus**: Prioritizes malfind and process context.
- **Custom**: Select exact plugins manually.
                """.strip(),
            },
            {
                "id": "progress-and-background",
                "title": "Progress and Background Execution",
                "content": """
- Analysis runs in a background thread.
- You can switch pages while plugins continue.
- Progress bar includes plugin count and ETA.
- If plugin failures occur, inspect **Plugin errors** in Home.
                """.strip(),
            },
            {
                "id": "reload-evidence",
                "title": "Analyze Another Dump",
                "content": """
1. Click **Clear Current** on Home.
2. Enter the new file path.
3. Select profile/plugins.
4. Start **Validate & Load** again.
                """.strip(),
            },
        ],
    },
    "investigation-guide": {
        "title": "Investigation Guide",
        "subtitle": "Recommended order to triage and validate findings.",
        "sections": [
            {
                "id": "triage-order",
                "title": "Recommended Triage Order",
                "content": """
1. **Dashboard**: identify critical and high findings first.
2. **Process Analysis**: inspect suspicious parents, command lines, and binaries.
3. **Network Analysis**: validate remote endpoints, listening ports, and beaconing.
4. **MITRE ATT&CK**: understand adversary behavior coverage.
5. **Timeline**: verify event sequence and incident narrative.
                """.strip(),
            },
            {
                "id": "ioc-validation",
                "title": "IOC Validation",
                "content": """
- Use **IOC Summary** to collect IPs, hashes, and suspicious artifacts.
- Cross-check high-impact IOCs with external threat intel.
- Keep false-positive notes before final reporting.
                """.strip(),
            },
            {
                "id": "risk-prioritization",
                "title": "Risk Prioritization",
                "content": """
- Start with findings scored near `10/10`.
- Prioritize findings with corroborating artifacts across pages.
- Treat single weak signals as **review** until validated.
                """.strip(),
            },
        ],
    },
    "ai-and-reports": {
        "title": "AI Analyst & Reports",
        "subtitle": "Use AI safely and generate professional outputs.",
        "sections": [
            {
                "id": "ai-analyst-usage",
                "title": "AI Analyst Usage",
                "content": """
- Ask targeted questions tied to current findings.
- Prefer prompts like:
  - “Summarize top 5 high-risk findings and remediation.”
  - “Explain likely attack chain from current evidence.”
- Treat AI output as analyst-assist, not final truth.
                """.strip(),
            },
            {
                "id": "provider-setup",
                "title": "Provider Setup",
                "content": """
Set provider in `.env` using `VOLATILEAI_AI_PROVIDER`:
- `ollama`
- `openai`
- `anthropic`
- `groq`
- `opentext`

If provider credentials are missing, the app remains usable in offline-safe mode.
                """.strip(),
            },
            {
                "id": "report-generation",
                "title": "Report Generation",
                "content": """
Go to **Reports** and generate one or more:
- Executive Summary
- Technical Analysis
- IOC Report
- MITRE ATT&CK Report

Use technical report after validating critical findings.
                """.strip(),
            },
            {
                "id": "output-quality-check",
                "title": "Output Quality Checklist",
                "content": """
- Confirm evidence filename and context are correct.
- Ensure critical findings are reviewed manually.
- Verify MITRE mapping aligns with observed artifacts.
- Remove uncertain claims before stakeholder sharing.
                """.strip(),
            },
        ],
    },
    "troubleshooting": {
        "title": "Troubleshooting",
        "subtitle": "Fix common setup and runtime issues quickly.",
        "sections": [
            {
                "id": "app-not-starting",
                "title": "App Not Starting",
                "content": """
```bash
source venv/bin/activate
pip install -r requirements.txt
./run.sh
```
                """.strip(),
            },
            {
                "id": "volatility-missing",
                "title": "Volatility Missing",
                "content": """
```bash
source venv/bin/activate
pip install volatility3
python3 -m volatility3 -h | head
```
                """.strip(),
            },
            {
                "id": "empty-results",
                "title": "No Findings or Empty Plugin Rows",
                "content": """
- Confirm dump is valid and supported.
- Switch from **Quick Triage** to **Full Analysis**.
- Include `malfind` if injection findings are expected.
- Review plugin errors in Home before re-running.
                """.strip(),
            },
            {
                "id": "performance-tips",
                "title": "Performance Tips",
                "content": """
- Start with **Quick Triage** first.
- Avoid multiple slow plugins in early triage.
- Run from SSD/local storage, not remote mounts.
- Keep only one active analysis job per session.
                """.strip(),
            },
        ],
    },
}


def _slugify_heading(text: str) -> str:
    """Create a stable HTML id from a markdown heading title."""
    cleaned = re.sub(r"`([^`]*)`", r"\1", text).strip().lower()
    cleaned = re.sub(r"[^\w\s-]", "", cleaned)
    cleaned = re.sub(r"[\s_-]+", "-", cleaned).strip("-")
    return cleaned or "section"


def _build_manual_view(markdown_text: str):
    """Return (index_entries, markdown_with_heading_ids)."""
    heading_pattern = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
    used_ids = {}
    index_entries = []
    rendered_lines = []

    for line in markdown_text.splitlines():
        match = heading_pattern.match(line)
        if not match:
            rendered_lines.append(line)
            continue

        level = len(match.group(1))
        heading_text = re.sub(r"\s+#+\s*$", "", match.group(2)).strip()

        base_id = _slugify_heading(heading_text)
        used_count = used_ids.get(base_id, 0)
        used_ids[base_id] = used_count + 1
        anchor_id = base_id if used_count == 0 else f"{base_id}-{used_count + 1}"

        if level >= 2:
            index_entries.append((level, heading_text, anchor_id))

        rendered_lines.append(f'<h{level} id="{anchor_id}">{heading_text}</h{level}>')

    return index_entries, "\n".join(rendered_lines)


def _query_param(name: str, default: str = "") -> str:
    value = st.query_params.get(name, default)
    if isinstance(value, list):
        value = value[0] if value else default
    return str(value).strip()


def _docs_styles():
    st.markdown(
        """
        <style>
        .va-docs-shell {
            margin-top: 0.1rem;
        }
        .va-docs-sidebar {
            position: sticky;
            top: 1rem;
            border: 1px solid #1f2c45;
            border-radius: 14px;
            background: linear-gradient(180deg, rgba(2,6,23,0.95) 0%, rgba(15,23,42,0.92) 100%);
            padding: 0.8rem;
        }
        .va-docs-sidebar-title {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #64748b;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        .va-docs-page-link, .va-docs-index-link {
            display: block;
            text-decoration: none !important;
            border-radius: 9px;
            margin-bottom: 0.22rem;
        }
        .va-docs-page-link {
            padding: 0.46rem 0.56rem;
            color: #cbd5e1 !important;
            border: 1px solid transparent;
            font-size: 0.83rem;
            font-weight: 600;
        }
        .va-docs-page-link:hover {
            border-color: #334155;
            background: rgba(15,23,42,0.7);
            color: #e2e8f0 !important;
        }
        .va-docs-page-link.active {
            border-color: rgba(56,189,248,0.5);
            background: rgba(14,165,233,0.12);
            color: #7dd3fc !important;
        }
        .va-docs-index-link {
            padding: 0.35rem 0.56rem;
            color: #94a3b8 !important;
            font-size: 0.78rem;
            border-left: 2px solid transparent;
        }
        .va-docs-index-link:hover {
            border-left-color: #38bdf8;
            background: rgba(15,23,42,0.5);
            color: #cbd5e1 !important;
        }
        .va-docs-body {
            border: 1px solid #1f2c45;
            border-radius: 14px;
            background: linear-gradient(160deg, rgba(2,6,23,0.9), rgba(15,23,42,0.8));
            padding: 1rem 1.05rem;
        }
        .va-docs-kicker {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #38bdf8;
            font-weight: 700;
            margin-bottom: 0.3rem;
        }
        .va-docs-subtitle {
            color: #94a3b8;
            margin-top: 0.25rem;
            margin-bottom: 1.1rem;
            font-size: 0.9rem;
            line-height: 1.55;
        }
        .va-docs-anchor {
            display: block;
            position: relative;
            top: -72px;
            visibility: hidden;
        }
        @media (max-width: 960px) {
            .va-docs-sidebar {
                position: static;
                margin-bottom: 0.8rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_guide_page(selected_slug: str, return_page_slug: str):
    selected_page = GUIDE_PAGES[selected_slug]
    nav_col, content_col = st.columns([1.08, 2.6], gap="large")

    with nav_col:
        page_links = []
        for slug, page in GUIDE_PAGES.items():
            active_class = "active" if slug == selected_slug else ""
            page_links.append(
                (
                    f"<a class='va-docs-page-link {active_class}' "
                    f"href='?docs=1&page={escape(return_page_slug)}&docs_page={escape(slug)}'>"
                    f"{escape(page['title'])}</a>"
                )
            )

        section_links = []
        for section in selected_page["sections"]:
            section_links.append(
                (
                    f"<a class='va-docs-index-link' "
                    f"href='?docs=1&page={escape(return_page_slug)}&docs_page={escape(selected_slug)}#{escape(section['id'])}'>"
                    f"{escape(section['title'])}</a>"
                )
            )

        st.markdown(
            (
                "<div class='va-docs-sidebar'>"
                "<div class='va-docs-sidebar-title'>Guide Pages</div>"
                f"{''.join(page_links)}"
                "<div class='va-docs-sidebar-title' style='margin-top:0.7rem'>On This Page</div>"
                f"{''.join(section_links)}"
                "</div>"
            ),
            unsafe_allow_html=True,
        )

    with content_col:
        content_blocks = [
            "<div class='va-docs-body'>",
            "<div class='va-docs-kicker'>Tool Guide</div>",
            f"<h2 style='margin:0'>{escape(selected_page['title'])}</h2>",
            f"<div class='va-docs-subtitle'>{escape(selected_page['subtitle'])}</div>",
        ]
        for section in selected_page["sections"]:
            content_blocks.append(f"<span id='{escape(section['id'])}' class='va-docs-anchor'></span>")
            content_blocks.append(f"### {section['title']}")
            content_blocks.append(section["content"])
        content_blocks.append("</div>")
        st.markdown("\n\n".join(content_blocks), unsafe_allow_html=True)


def render_documentation():
    page_header(
        "Guide",
        subtitle="Tool-style usage documentation with indexed navigation",
        icon="",
    )

    _docs_styles()

    requested_slug = _query_param("docs_page", "quick-start").lower()
    selected_slug = requested_slug if requested_slug in GUIDE_PAGES else "quick-start"
    return_page_slug = _query_param("page", "home").lower() or "home"

    st.markdown(
        """
        <div style='margin:0.2rem 0 0.95rem 0;padding:0.85rem 0.95rem;border:1px solid #334155;border-radius:12px;background:rgba(15,23,42,0.45)'>
            <div style='font-size:0.92rem;font-weight:700;color:#e2e8f0;margin-bottom:0.35rem'>How to use this guide</div>
            <div style='font-size:0.83rem;color:#94a3b8;line-height:1.58'>
                Use <strong>Guide Pages</strong> on the left to switch topics. Use <strong>On This Page</strong> to jump directly to a section.
                This guide is task-oriented for analysts using VolatileAI in real investigations.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _render_guide_page(selected_slug, return_page_slug)

    docs_path = Path(__file__).resolve().parents[2] / "DOCUMENTATION.md"
    if not docs_path.exists():
        info_banner("Technical reference file not found.", type_="warning")
        return

    try:
        content = docs_path.read_text(encoding="utf-8")
    except OSError as exc:
        st.error(f"Unable to read technical reference: {exc}")
        return

    index_entries, manual_content = _build_manual_view(content)
    with st.expander("Full Technical Reference (DOCUMENTATION.md)", expanded=False):
        if index_entries:
            st.markdown("#### Index")
            index_lines = []
            for level, title, anchor in index_entries:
                indent = "&nbsp;" * max(0, (level - 2) * 4)
                index_lines.append(f"{indent}- [{title}](#{anchor})")
            st.markdown("\n".join(index_lines), unsafe_allow_html=True)
            st.divider()
        st.markdown(manual_content, unsafe_allow_html=True)
