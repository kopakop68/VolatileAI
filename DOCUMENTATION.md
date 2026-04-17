# VolatileAI - Comprehensive Technical Documentation (Paper-Ready)

Version: 1.0.0  
Project Type: AI-assisted memory forensics platform  
Primary Stack: Python, Streamlit, Volatility 3, Plotly, fpdf2

---

## 1. Abstract

VolatileAI is an interactive memory forensics investigation platform designed to convert raw memory artifacts into analyst-ready findings, ATT&CK mappings, and narrative reports. It combines three major layers:

1. Acquisition and parsing layer using Volatility 3 plugins.
2. Deterministic heuristic detection layer for suspicious process, network, injection, DLL, and service activity.
3. Analyst assistance layer using multi-provider LLM support (Ollama/OpenAI-compatible/Anthropic/Groq/OpenText-compatible) plus cached offline responses.

The system is implemented as a Streamlit web application with modular page-based analysis, persistent session state, report export, and operational logging.

---

## 2. Problem Statement and Motivation

Memory forensics tools provide deep artifacts but require substantial analyst effort to correlate indicators and prioritize risk. Typical bottlenecks:

1. Plugin output fragmentation across processes, sockets, command lines, and memory regions.
2. High cognitive load in triage and attack-chain reconstruction.
3. Repetitive report-writing effort for incident communication.
4. Difficulty balancing detection sensitivity with false-positive control.

VolatileAI addresses this by combining structured plugin execution, explainable heuristics, ATT&CK context, and AI-assisted interpretation.

---

## 3. Project Goals

1. Load and validate real memory dump files in a user-friendly UI.
2. Execute a standard plugin suite and preserve plugin-level diagnostics.
3. Detect suspicious behaviors with deterministic rules and risk scoring.
4. Map findings to MITRE ATT&CK for strategic visibility.
5. Provide analyst chat and auto-summary features with provider flexibility.
6. Export professional reports for management and technical stakeholders.
7. Maintain practical runtime operability (live logs, progress feedback, no restart required for new evidence).

---

## 4. Current Repository Snapshot

### 4.1 Top-level Files

1. `app.py` - Streamlit entrypoint, session initialization, sidebar navigation, page routing.
2. `config.py` - Canonical runtime configuration, env overrides, normalization/validation.
3. `run.sh` - Runtime launcher with env autoload, localhost-safe binding, live logging.
4. `setup.sh` - Environment bootstrap and dependency installation.
5. `requirements.txt` - Python dependency pins/ranges.
6. `.env.example` - User-editable runtime/provider template.
7. `.gitignore` - Ignore venv, logs, local secrets, runtime artifacts.
8. `README.md` - User-level setup and feature overview.
9. `DOCUMENTATION.md` - This technical reference.
10. `__init__.py` - Empty package marker.

### 4.2 Core Modules (`core/`)

1. `core/volatility_engine.py`
2. `core/anomaly_detector.py`
3. `core/mitre_mapper.py`
4. `core/ai_engine.py`
5. `core/scenario_loader.py`
6. `core/__init__.py` (empty)

### 4.3 UI Modules (`ui/`)

1. `ui/pages/home.py`
2. `ui/pages/dashboard.py`
3. `ui/pages/process_analysis.py`
4. `ui/pages/network_analysis.py`
5. `ui/pages/mitre_page.py`
6. `ui/pages/timeline_page.py`
7. `ui/pages/ai_chat.py`
8. `ui/pages/ioc_summary.py`
9. `ui/pages/reports_page.py`
10. `ui/components/charts.py`
11. `ui/components/metrics.py`
12. `ui/styles/theme.css`
13. `ui/__init__.py`, `ui/pages/__init__.py`, `ui/components/__init__.py` (empty markers)

### 4.4 Reporting

1. `reports/report_generator.py`
2. `reports/__init__.py` (empty)
3. `reports/output/` (runtime-generated PDFs; currently empty)

### 4.5 Runtime Config

1. `.streamlit/config.toml` - dark theme, localhost bind, upload size limit, telemetry off.

### 4.6 Data Directories (Current State)

1. `data/cached_responses/` - present, currently empty.
2. `data/demo_scenarios/` - present, currently empty.
3. `data/mitre/` - present, currently empty.
4. `evidence/` - currently empty.
5. `logs/` - contains runtime log files from launches.

Note: Code supports demo scenarios and cache files, but these directories are empty in the current workspace state.

---

## 5. System Architecture

## 5.1 High-level Layering

1. Presentation Layer (Streamlit UI pages/components)
2. Analysis Layer (Volatility wrapper + heuristic detector + ATT&CK mapper)
3. AI Layer (provider routing + context prompt + fallback cache)
4. Reporting Layer (FPDF generator)
5. Runtime Layer (shell scripts, environment variables, logs)

## 5.2 Main Runtime Sequence

1. `run.sh` activates venv, loads `.env`, starts Streamlit with line-buffered output.
2. `app.py` initializes singleton-like engines in `st.session_state`.
3. User loads evidence in Home page.
4. `VolatilityEngine` validates file and executes plugins.
5. `AnomalyDetector` converts plugin output into ranked `Finding` objects.
6. `MitreMapper` structures ATT&CK technique/tactic data.
7. UI pages consume shared session state for visualization and analysis.
8. `AIEngine` answers investigation prompts from configured provider or cache.
9. `ReportGenerator` produces downloadable PDF reports.

---

## 6. Runtime Entry and Control Scripts

## 6.1 `run.sh`

Responsibilities:

1. Activates project venv.
2. Sets `PYTHONPATH` to project root.
3. Loads `.env` automatically if present.
4. Creates timestamped log file in `logs/`.
5. Uses `stdbuf -oL -eL` + `tee` to keep logs live in terminal and persisted to disk.
6. Defaults Streamlit bind to localhost (`127.0.0.1`) for safer local execution.

Operational behavior:

1. If port is busy, Streamlit exits and logs the reason.
2. All startup/runtime output is mirrored to `logs/volatileai_YYYYMMDD_HHMMSS.log`.

## 6.2 `setup.sh`

Responsibilities:

1. Creates venv if missing.
2. Installs dependencies from `requirements.txt` (preferred path).
3. Fallback install command includes `volatility3` explicitly.
4. Creates required runtime directories (`reports/output`, `evidence`, `logs`, `data/*`).
5. Prints warning if `vol` CLI is not detected after install.

---

## 7. Configuration System (`config.py`)

`config.py` is not a flat constant file; it is a normalization/validation pipeline.

## 7.1 Environment Parsing Helpers

1. `_env_str`, `_env_int`, `_env_csv`
2. `_normalize_supported_formats`, `_normalize_plugin_list`
3. `_normalize_ai_provider`, `_normalize_ollama_url`
4. `_normalize_windows_processes`, `_normalize_map_of_string_lists`
5. `_normalize_homoglyph_map`, `_normalize_risk_levels`

## 7.2 Key Runtime Variables

1. Paths: `DATA_DIR`, `DEMO_DIR`, `CACHE_DIR`, `EVIDENCE_DIR`, `REPORTS_DIR`.
2. AI provider: `VOLATILEAI_AI_PROVIDER` with allowed values `ollama`, `openai`, `anthropic`, `groq`, `opentext`.
3. Provider credentials and model selection.
4. Plugin lists for Windows/Linux.
5. Risk color/threshold definitions.
6. Detection baselines: suspicious parents, ports, homoglyph map.

## 7.3 Validation Lifecycle

At import time:

1. `_apply_environment_overrides()`
2. `validate_and_normalize_config()`

This ensures all directories exist and values are safe/consistent before runtime usage.

---

## 8. Application Shell (`app.py`)

## 8.1 Session State Initialization

`init_session_state()` stores long-lived runtime objects:

1. `vol_engine`
2. `detector`
3. `mitre_mapper`
4. `ai_engine`
5. `scenario_loader`

and analysis state:

1. `evidence_loaded`
2. `evidence_info`
3. `current_scenario`
4. `findings`
5. `plugin_results`
6. `analysis_complete`
7. `chat_history`

## 8.2 Sidebar and Routing

Sidebar includes:

1. app branding/version
2. radio navigation across 9 pages
3. system status lines (Volatility readiness, AI provider message, evidence state)

Routing is simple and explicit via page label matching.

---

## 9. Core Analysis Modules

## 9.1 `core/volatility_engine.py`

### Data models

1. `EvidenceFile`
2. `PluginResult`

### Important methods

1. `_check_volatility()` checks `vol --help` first, then Python module fallback.
2. `validate_evidence()` validates existence, extension, computes MD5/SHA-256.
3. `run_plugin()` executes plugin with JSON output, logs progress lines, handles timeout/parse failures.
4. `run_all_plugins()` executes configured plugin set and supports `progress_callback(done, total, plugin, phase)`.
5. `load_demo_results()` adapts static scenario JSON to `PluginResult` format.

### Recent behavior

1. Live plugin logging integrated (`[VolatilityEngine HH:MM:SS] ...`).
2. Plugin-level progress callback now used by UI for progress bar and ETA.

## 9.2 `core/anomaly_detector.py`

Defines `Finding` and orchestrates rule-based analysis.

Categories:

1. process
2. network
3. injection
4. dll
5. persistence

Pipeline:

1. `_analyze_processes`
2. `_analyze_network`
3. `_analyze_injections`
4. `_analyze_dlls`
5. `_analyze_services`

Notable rules:

1. suspicious parent-child process chains
2. system process path anomalies
3. homoglyph masquerading
4. suspicious command-line regex indicators
5. suspicious/listening ports
6. malfind-based injection severity boosts
7. DLL load path anomalies
8. service binary and interpreter misuse

False-positive reductions currently implemented:

1. process instance anomaly requires larger overage (`expected + 2`) and deduplicates alert per process name.
2. expected-parent anomaly suppresses unknown/idle noise and uses lower severity.
3. high-frequency network alert requires stronger threshold (`count >= 12`).

## 9.3 `core/mitre_mapper.py`

1. Hardcoded ATT&CK technique knowledge base via `MitreTechnique` dataclass.
2. `map_findings()` groups findings by technique ID.
3. `get_tactic_heatmap_data()` returns tactic-wise structures for bubble heatmap.
4. `get_detected_techniques()` returns sorted technique summaries with severity/count.
5. `get_unique_tactics()` for KPI usage.

## 9.4 `core/ai_engine.py`

### Provider model

1. runtime provider selected from env-driven `AI_PROVIDER`.
2. connectivity checked per provider.
3. model labels and provider status exposed to UI.

### Routing

`ask()` resolution order:

1. exact cache key match
2. fuzzy cache match (Jaccard-like overlap threshold)
3. live provider query
4. fallback guidance string

### Provider implementations

1. Ollama generate endpoint
2. OpenAI-compatible chat completions (OpenAI/Groq/OpenText-compatible)
3. Anthropic messages API

### Context policy and false-positive control

`set_context()` injects instructions that now explicitly:

1. discourage confirmed-malicious claims without multiple independent indicators
2. require confidence framing for weak evidence
3. separate high-confidence vs low-confidence hypotheses

This affects local and remote providers equally because all route through shared context construction.

## 9.5 `core/scenario_loader.py`

1. Loads optional `scenario_*.json` from `data/demo_scenarios`.
2. Lists scenarios and plugin datasets.
3. Builds timeline event list from process/network/findings.

Current runtime note: scenario directory exists but is empty in this workspace.

---

## 10. UI Pages (`ui/pages`)

## 10.1 `home.py`

Primary operational page.

Responsibilities:

1. render hero section
2. validate and load memory dump path
3. maintain evidence details card across reruns/tab switches
4. reset current analysis (`Clear Current`) without server restart
5. show animated loading indicator during plugin run
6. show real plugin progress percentage + current plugin + ETA
7. clear loader animation after completion
8. summarize plugin success count and row-return count
9. show plugin error expander
10. handoff findings context to AI engine

Important UX behavior:

1. Same Streamlit instance can process multiple memory dumps; no need to rerun `run.sh` for each file.
2. Analysis state is reset in-session before each new load.

## 10.2 `dashboard.py`

Responsibilities:

1. top-level KPIs (findings, critical, ATT&CK count, max risk)
2. risk donut chart
3. findings-by-category chart
4. top critical findings cards
5. investigation priorities summary block
6. plugin success diagnostics when findings are empty

## 10.3 `process_analysis.py`

Responsibilities:

1. process tree visualization with risk coloring
2. detailed process table with suspicious row highlighting
3. suspicious process cards
4. command-line snippets per finding PID
5. unusual parent-child relationship cards

Dataframe normalization to string values is used to avoid Arrow conversion warnings in Streamlit.

## 10.4 `network_analysis.py`

Responsibilities:

1. network KPI cards
2. graph visualization (local vs remote endpoints)
3. filterable connection table (state/PID)
4. suspicious connection cards

Dataframe columns are string-normalized to prevent mixed-type serialization warnings.

## 10.5 `mitre_page.py`

Responsibilities:

1. technique/tactic KPIs
2. ATT&CK bubble heatmap
3. technique summary table with severity styling
4. expandable technique details and ATT&CK links

Implementation note: uses `Styler.map` (not deprecated `applymap`) for current pandas compatibility.

## 10.6 `timeline_page.py`

Responsibilities:

1. event KPIs
2. timeline chart
3. category/risk filters
4. event cards and detail expanders

Current chart implementation avoids overlap via category-axis indexing plus jitter in chart component.

## 10.7 `ai_chat.py`

Responsibilities:

1. provider status indicator
2. quick-action analysis buttons
3. conversational chat input/history
4. suggested questions when history is empty

## 10.8 `ioc_summary.py`

Responsibilities:

1. IOC extraction from findings
2. tabbed IOC views (IP/process/ports/services/techniques)
3. risk-level styled IOC tables
4. export text area
5. AI-generated IOC narrative panel

## 10.9 `reports_page.py`

Responsibilities:

1. report type selection and metadata capture
2. report preview generation
3. trigger PDF generation and download button
4. optional AI summary preview expander

---

## 11. UI Components

## 11.1 `ui/components/charts.py`

Chart factories:

1. `create_risk_donut`
2. `create_category_bar`
3. `create_process_tree`
4. `create_network_graph`
5. `create_timeline` (jittered category points + hover details)
6. `create_mitre_heatmap`

## 11.2 `ui/components/metrics.py`

HTML-based reusable elements:

1. `page_header`
2. `risk_badge`
3. `stat_card`
4. `finding_card`
5. `info_banner`

---

## 12. Theme and Runtime UI Settings

## 12.1 `ui/styles/theme.css`

Main styling concepts:

1. dark forensic visual identity
2. polished sidebar/tabs/buttons/cards
3. strong contrast for tables and text inputs
4. progress bar and scrollbar customizations

## 12.2 `.streamlit/config.toml`

1. dark base theme with project palette
2. server bound to localhost (`127.0.0.1`)
3. default port `8502`
4. upload size cap `5000` MB
5. usage stats disabled

---

## 13. Reporting Module (`reports/report_generator.py`)

Two classes:

1. `ForensicReportPDF` (FPDF subclass for consistent header/footer/sections)
2. `ReportGenerator` (dispatches report type and writes PDF bytes)

Supported report flows:

1. Executive Summary
2. Technical Analysis
3. IOC Report
4. MITRE ATT&CK Report

Output is retained in memory and exposed to UI via `st.download_button`.

---

## 14. End-to-End Data Flow

1. User starts app via `run.sh`.
2. Home page accepts evidence path.
3. File validated and hashed.
4. Plugins executed sequentially with callback updates.
5. `plugin_results` stored in session.
6. detector converts plugin rows to findings.
7. findings passed to dashboards/pages/AI/reporting.
8. analyst iterates, chats, and exports report.

---

## 15. Session State Contract

Primary keys and intent:

1. `vol_engine`: plugin orchestration object
2. `detector`: finding generation object
3. `mitre_mapper`: ATT&CK mapping helper
4. `ai_engine`: AI provider/caching layer
5. `scenario_loader`: optional scenario helper
6. `evidence_loaded`: gate for analysis pages
7. `evidence_info`: currently loaded file metadata
8. `plugin_results`: per-plugin structured output
9. `findings`: unified alert list
10. `current_scenario`: scenario context when used
11. `analysis_complete`: run-finished flag
12. `chat_history`: AI chat transcript

---

## 16. Logging and Observability

Sources:

1. `run.sh` produces timestamped log files and mirrors output live.
2. `VolatilityEngine` emits plugin progress/failure logs with timestamps.
3. Streamlit runtime warnings/exceptions appear in same launcher log stream.

Typical operational checks:

1. confirm plugin completion count via `Completed plugin:` lines
2. inspect `Plugin failed` messages and stderr snippets
3. verify AI provider status via sidebar message

---

## 17. Security and Operational Notes

1. `.env` is ignored by git.
2. API keys should never be committed.
3. default localhost bind reduces accidental exposure.
4. report PDFs may include sensitive host/process/network data; treat output as confidential.
5. memory dumps can contain credentials/secrets; enforce access controls on evidence storage.

---

## 18. Known Limitations

1. plugin execution is sequential; no parallel plugin scheduling.
2. fallback to `python3 -m volatility3` may fail in environments where module invocation differs.
3. ATT&CK technique catalog is static in code, not dynamically synced.
4. AI quality depends on provider/model availability and context completeness.
5. heuristic detections are rule-based; still subject to environment-specific false positives/false negatives.

---

## 19. Suggested Experimental Evaluation for Your Paper

For a strong major-project paper, evaluate on at least 3 axes.

## 19.1 Detection Utility

1. Prepare labeled test cases or curated memory dumps.
2. Measure precision-like behavior by manually validating top N findings.
3. Report false-positive trends before/after threshold tuning.

## 19.2 Analyst Efficiency

1. Time-to-triage comparison: raw Volatility workflow vs VolatileAI workflow.
2. Time-to-report comparison using built-in PDF export.
3. Measure reduction in manual correlation steps.

## 19.3 Explainability and Actionability

1. Evaluate whether findings include enough artifact context (PID/IP/path/cmdline).
2. Evaluate ATT&CK mapping coverage and relevance.
3. Evaluate AI outputs for confidence language and overclaim suppression.

---

## 20. Reproducibility Procedure

1. Clone repository.
2. Run `./setup.sh`.
3. Copy `.env.example` to `.env` and configure provider if needed.
4. Start with `./run.sh`.
5. Load memory evidence via Home page.
6. Validate plugin completion and findings in Dashboard.
7. Export one Technical Analysis report.
8. Archive logs from `logs/` for experiment traceability.

---

## 21. File-by-File Quick Reference Table

| File | What It Does |
|------|---------------|
| `app.py` | Streamlit app bootstrap, routing, global session object setup |
| `config.py` | Runtime config parsing/normalization, provider selection, plugin/risk defaults |
| `run.sh` | Runtime entry, `.env` loading, safe bind, live log tee |
| `setup.sh` | One-time setup and dependency install |
| `requirements.txt` | Python package dependencies |
| `.env.example` | Template env vars for provider/runtime control |
| `.streamlit/config.toml` | Streamlit server/theme/browser config |
| `core/volatility_engine.py` | Evidence validation, plugin exec, progress callback, plugin result model |
| `core/anomaly_detector.py` | Heuristic detections and risk scoring |
| `core/mitre_mapper.py` | ATT&CK technique model and mapping transforms |
| `core/ai_engine.py` | Provider routing, prompt context, cache/fuzzy fallback |
| `core/scenario_loader.py` | Optional scenario JSON loading and timeline synthesis |
| `ui/pages/home.py` | Evidence loading workflow, progress UI, reset workflow |
| `ui/pages/dashboard.py` | KPIs, charts, top findings, priorities |
| `ui/pages/process_analysis.py` | Process tree, process table, suspicious process drilldown |
| `ui/pages/network_analysis.py` | Network graph/table/filtering and suspicious connections |
| `ui/pages/mitre_page.py` | ATT&CK metrics, heatmap, technique detail panels |
| `ui/pages/timeline_page.py` | Event timeline visualization/filtering/details |
| `ui/pages/ai_chat.py` | AI chat experience and quick actions |
| `ui/pages/ioc_summary.py` | IOC extraction tabs and export panel |
| `ui/pages/reports_page.py` | Report configuration, generation, download |
| `ui/components/charts.py` | Plotly chart factories |
| `ui/components/metrics.py` | Reusable HTML UI widgets |
| `ui/styles/theme.css` | Global dark forensic theme |
| `reports/report_generator.py` | PDF report rendering engine |
| `README.md` | User-facing quickstart and feature list |
| `.gitignore` | Ignore local/secrets/runtime artifacts |
| `__init__.py` files | Package markers |

---

## 22. What Changed Recently (Important for Paper Accuracy)

1. Added progress callback path from engine to UI for plugin-level progress and ETA.
2. Added in-session multi-evidence handling and clear/reset workflow in Home page.
3. Improved live log behavior in launcher with line-buffered stream.
4. Replaced deprecated DataFrame Styler APIs with current-compatible usage.
5. Reduced false-positive pressure in anomaly heuristics and AI prompt guidance.
6. Improved timeline readability by avoiding overplot overlap patterns.

---

## 23. Conclusion

VolatileAI is a modular, end-to-end memory investigation platform that sits between raw plugin output and analyst decision-making. Its value lies in deterministic detection logic, coherent ATT&CK contextualization, practical AI assistance, and report automation. The codebase is structured for explainability and iterative improvement, making it suitable for both academic evaluation and real-world SOC prototyping.

---

Prepared for major-project documentation and paper-writing use.
