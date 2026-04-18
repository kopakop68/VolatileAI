# VolatileAI - Complete Technical Documentation

Version: 1.0.0  
Scope: Current live codebase (Windows-focused memory forensics)

---

## 1) What VolatileAI Is

VolatileAI is an interactive memory-forensics application built with Streamlit. It orchestrates Volatility 3 plugin execution, applies deterministic heuristics to produce findings, maps findings to MITRE ATT&CK, supports AI-assisted analyst workflows, and generates PDF reports.

Core design goals:
1. Evidence-first workflow (real memory dump path -> plugin run -> findings).
2. Transparent, explainable detection logic (rule-based, scored findings).
3. Analyst productivity (charts, filters, AI assistance, report export).
4. Safe local-default runtime (localhost binding, environment-driven configuration).

---

## 2) End-to-End Runtime Flow

1. User starts the app with run.sh.
2. app.py initializes engines in Streamlit session state.
3. Home page validates evidence path and computes hashes.
4. Home page starts background analysis thread.
5. core/volatility_engine.py runs selected plugins and reports progress.
6. core/anomaly_detector.py converts plugin output into ranked Finding objects.
7. core/mitre_mapper.py transforms findings into ATT&CK summaries.
8. UI pages render findings and derived KPIs/charts.
9. core/ai_engine.py answers analyst prompts using configured provider.
10. reports/report_generator.py builds downloadable PDF reports.

---

## 3) Repository Structure and File Roles

### 3.1 Top-level files

- app.py
  - Main Streamlit entrypoint.
  - Initializes global session state and routes all pages.

- config.py
  - Canonical runtime configuration module.
  - Parses environment variables, normalizes values, validates directories.

- run.sh
  - Runtime launcher.
  - Activates venv, loads .env, starts Streamlit with live log tee.

- setup.sh
  - Setup bootstrap.
  - Creates venv, installs dependencies, creates runtime directories.

- requirements.txt
  - Python dependencies.

- README.md
  - User-facing setup and usage guidance.

- DOCUMENTATION.md
  - This technical reference.

- .env.example
  - Template environment file for provider/runtime settings.

- .streamlit/config.toml
  - Streamlit server/theme defaults.

- __init__.py
  - Package marker (no runtime logic).

- .gitignore
  - Ignore rules for secrets, venv, build/runtime artifacts.

### 3.2 Core directory

- core/volatility_engine.py
- core/anomaly_detector.py
- core/mitre_mapper.py
- core/ai_engine.py
- core/scenario_loader.py
- core/__init__.py (package marker)

### 3.3 UI directory

- ui/pages/home.py
- ui/pages/dashboard.py
- ui/pages/process_analysis.py
- ui/pages/network_analysis.py
- ui/pages/mitre_page.py
- ui/pages/timeline_page.py
- ui/pages/ai_chat.py
- ui/pages/ioc_summary.py
- ui/pages/reports_page.py
- ui/components/charts.py
- ui/components/metrics.py
- ui/styles/theme.css
- ui/__init__.py, ui/pages/__init__.py, ui/components/__init__.py (package markers)

### 3.4 Reports

- reports/report_generator.py
- reports/__init__.py (package marker)
- reports/output/ (generated PDFs)

### 3.5 Runtime directories

- evidence/ (user-supplied memory files)
- logs/ (launcher/runtime logs)

---

## 4) Runtime Scripts and Environment

## 4.1 run.sh

Purpose:
1. Activates venv and sets PYTHONPATH.
2. Loads .env if present.
3. Creates logs/ and timestamped log file.
4. Starts Streamlit with localhost-safe defaults.

Important behavior:
1. Default bind: 127.0.0.1.
2. Default port: 8502.
3. Uses stdbuf + tee for line-buffered live logs and persisted logs.

## 4.2 setup.sh

Purpose:
1. Create venv (if missing).
2. Install dependencies from requirements.txt.
3. Create required directories (reports/output, evidence, logs).
4. Warn if vol CLI is not found.

## 4.3 .env.example

Defines runtime options for:
1. AI provider selection (ollama/openai/anthropic/groq/opentext).
2. Per-provider base URL, API key, and model.
3. Global AI timeout.

## 4.4 .streamlit/config.toml

Controls:
1. Theme colors and dark mode defaults.
2. Server bind, port, and max upload size.
3. Usage telemetry setting.

---

## 5) app.py (Application Shell)

Functions:

1. init_session_state()
- Creates/stores long-lived engine objects in st.session_state.
- Initializes analysis state keys and synchronization lock.

2. load_css()
- Loads ui/styles/theme.css into Streamlit app if file exists.

3. main()
- Sets Streamlit page config.
- Calls init_session_state() and global completed-analysis apply hook.
- Renders sidebar status and navigation.
- Routes page rendering by selected section.

Session state contract created here:
1. Engines: vol_engine, detector, mitre_mapper, ai_engine, scenario_loader.
2. Analysis state: evidence_loaded, evidence_info, plugin_results, findings.
3. Progress state: analysis_status, analysis_task_thread, analysis_lock.
4. UX state: analysis_complete, chat_history, current_scenario.

---

## 6) config.py (Normalization and Validation Pipeline)

### 6.1 Helper functions

- _env_str(name, default)
  - Reads environment variable as trimmed string.

- _env_int(name, default)
  - Reads integer env var with safe fallback.

- _split_csv(value)
- _env_csv(name)
  - CSV parsing for environment list values.

- _to_int_list(values)
  - Parses and validates port lists (1..65535), order-preserving dedupe.

- _normalize_supported_formats(values, defaults)
  - Normalizes extensions (lowercase, ensure leading dot).

- _normalize_plugin_list(values, defaults)
  - Cleans/deduplicates plugin identifiers.

- _normalize_lowercase_list(values, defaults)
  - Lowercases and deduplicates string lists.

- _normalize_ollama_url(url, default)
  - Ensures valid Ollama URL shape.

- _normalize_ai_provider(provider)
  - Restricts provider to allowed set.

- _normalize_windows_processes(values, defaults)
  - Validates expected path/parent/instance metadata.

- _normalize_map_of_string_lists(values, defaults)
  - Validates dict[str, list[str]] maps (e.g., suspicious parents).

- _normalize_homoglyph_map(values, defaults)
  - Normalizes homoglyph lookup map.

- _normalize_risk_levels(values, defaults)
  - Validates risk colors/thresholds and enforces descending thresholds.

### 6.2 Runtime constants and model

Primary groups:
1. App metadata (name, version, tagline).
2. Directories (BASE_DIR, EVIDENCE_DIR, REPORTS_DIR).
3. Supported evidence formats.
4. AI provider and credentials.
5. Risk level color/threshold config.
6. Volatility plugin lists (Windows + Linux lists).
7. Detection baselines:
   - WINDOWS_SYSTEM_PROCESSES
   - SUSPICIOUS_PARENTS
   - BENIGN_INJECTION_PROCESSES
   - SUSPICIOUS_PORTS / KNOWN_C2_PORTS
   - HOMOGLYPH_MAP

### 6.3 Finalization functions

- _apply_environment_overrides()
  - Applies env overrides for formats, plugin lists, and port lists.

- validate_and_normalize_config()
  - Ensures all values are safe/usable and directories exist.

Module import behavior:
1. _apply_environment_overrides() is called.
2. validate_and_normalize_config() is called.

---

## 7) core/volatility_engine.py

Classes:

1. EvidenceFile (dataclass)
- Stores validated evidence metadata and hashes.
- Fields: path, filename, size, format, md5, sha256, is_valid, etc.

2. PluginResult (dataclass)
- Stores per-plugin execution result.
- Fields: success flag, parsed rows, error text, raw output, row_count.

3. VolatilityEngine

Key methods:

- _check_volatility()
  - Checks vol CLI first, then python -m volatility3 fallback.

- _log(message)
  - Prints timestamped runtime log lines.

- _run_vol_command_streaming(cmd, timeout=300)
  - Executes command and collects output while streaming stderr lines to logs.

- validate_evidence(file_path)
  - Confirms file existence and supported extension.
  - Computes MD5/SHA-256 (synchronous).
  - Returns EvidenceFile.

- run_plugin(plugin_name, file_path=None)
  - Executes single plugin in JSON mode.
  - Attempts vol CLI, then module fallback.
  - Parses JSON rows into PluginResult.

- run_all_plugins(file_path, os_type="windows", progress_callback=None, plugins=None)
  - Runs plugin list sequentially.
  - Supports caller-provided plugin subset.
  - Validates plugin names against known list and deduplicates while preserving order.
  - Emits progress_callback(done, total, plugin, phase).

- get_results()
  - Returns cached plugin result dict.

- load_demo_results(scenario_data)
  - Adapts injected scenario dict to PluginResult objects.

- _hash_file(path, algo)
- _human_size(size_bytes)

How this file is used:
1. Created once in app.py session state.
2. Home page calls validate_evidence() and run_all_plugins().
3. All downstream pages read st.session_state.plugin_results.

---

## 8) core/anomaly_detector.py

Classes:

1. Finding (dataclass)
- Unified detection artifact used by all pages.
- Fields: category, artifact_id, title, description, risk_score, evidence, techniques, timestamp, triage_status.
- Properties: risk_level, requires_manual_review.

2. AnomalyDetector

Primary pipeline:

- analyze_all(plugin_results)
  - Entry point.
  - Selects plugin outputs, builds process index, invokes analyzers, sorts findings by risk.

Supporting methods:

- _build_process_index(processes)
  - Normalizes process rows into int-keyed PID index with parent and timestamp metadata.

- _analyze_processes(process_index, cmdlines)
  - Runs multiple process checks and instance-count checks.

- _is_expected_smss_child(name, parent_name)
  - Suppresses expected csrss/winlogon/wininit parent noise.

- _check_path_anomaly(name, cmdline, pid, raw)
  - Detects system process path mismatches.

- _check_parent_anomaly(name, parent_name, pid, raw)
  - Parent-child anomaly and suspicious parent checks.

- _check_scripting_runtime_parent(name, parent_name, ppid, pid, raw)
  - Flags runtime interpreters under suspicious service-host parents.
  - Unresolved-parent fallback now gated to Session 0 only.

- _check_name_spoofing(name, pid, raw)
  - Homoglyph-based masquerading detection.

- _check_suspicious_cmdline(name, cmdline, pid, raw)
  - Regex signatures (encoded PowerShell, download cradles, vssadmin abuse, etc.).

- _analyze_network(connections)
  - Deduplicates endpoint findings via endpoint_findings map.
  - Aggregates suspicious remote port, high-frequency beaconing, and suspicious local listening port signals.
  - Emits finding only when reasons list is non-empty.

- _analyze_injections(malfind_data, process_index)
  - Uses malfind results, dedupes by PID.
  - Adjusts severity by protection and process context.
  - Applies benign-injection triage list.

- _analyze_dlls(dlllist_data)
  - Flags DLLs loaded from temp/download-like paths.
  - Normalizes path separators before matching.

- _analyze_services(svcscan_data)
  - Flags suspicious service binary paths and interpreter-based service binaries.

- get_risk_summary()
- get_findings_by_category()

How this file is used:
1. Home page invokes detector after plugin completion.
2. Findings are shared to all pages and report generation.

---

## 9) core/mitre_mapper.py

Data model:

- MitreTechnique (dataclass)
  - technique_id, name, tactic, description, detection, url.

Static catalogs:
1. MITRE_TECHNIQUES dict.
2. TACTIC_ORDER list.

Class:

- MitreMapper

Methods:

- get_technique(technique_id)
- map_findings(findings)
  - Builds technique_id -> list[Finding].

- get_tactic_heatmap_data(findings)
  - Returns tactic-keyed data with count and max severity.

- get_detected_techniques(findings)
  - Returns sorted list of technique summaries.

- get_unique_tactics(findings)

How this file is used:
1. MITRE page KPIs, table, and detail panels.
2. MITRE heatmap chart input.
3. MITRE report generation.

---

## 10) core/ai_engine.py

Class:

- AIEngine

State:
1. Configured provider and active base URL.
2. Context payload for AI prompts.
3. Confirmed MITRE ID string used to constrain model references.

Connectivity and provider checks:

- _candidate_base_urls()
- check_ollama()
- _check_openai_compatible(base_url, api_key)
- check_provider()
- has_model()
- is_available property
- provider_status()

Rate-limit and transient handling:

- _retry_after_seconds(response, default_delay)
- _is_transient_status(status_code)
- _post_with_backoff(...)
  - Retries transient statuses (429/5xx) with bounded backoff.

Context and prompt path:

- set_context(findings_summary, plugin_data_summary, confirmed_mitre_ids="")
  - Injects analysis evidence and guardrails into shared context.

- _system_prompt()
  - Requires MITRE references to only use confirmed IDs.

Query routing:

- ask(question, scenario_id="")
  - Dispatches by provider.

- _query_ollama(question)
- _query_openai_compatible(provider_name, base_url, api_key, model, question)
- _query_anthropic(question)
- _extract_error_text(response)
- _memory_error_response(details)
- _offline_response(question)

Quick-analysis helpers:

- get_auto_analysis()
- get_attack_narrative()
- get_ioc_list()
- get_recommendations()

Important note:
1. Current behavior is strict offline response when provider is unavailable.
2. No synthetic/mock response generation is used.

---

## 11) core/scenario_loader.py

Class:

- ScenarioLoader

Current behavior:
1. Scenario loading is effectively disabled (empty scenario store).
2. Helper methods still exist and return empty/default structures if no scenario data.

Methods:

- _load_scenarios()
- list_scenarios()
- get_scenario(scenario_id)
- get_plugin_data(scenario_id)
- get_processes(scenario_id)
- get_connections(scenario_id)
- get_cmdlines(scenario_id)
- get_timeline_events(scenario_id, findings=None)

---

## 12) UI Pages

## 12.1 ui/pages/home.py

Purpose:
1. Evidence load/reset workflow.
2. Plugin selection preset/custom UI.
3. Background analysis threading + progress rendering.
4. Evidence metadata display.

Constants:
1. PLUGIN_LABELS
2. PRESET_PROFILES

Functions:

- _start_background_analysis(file_path, evidence, plugins=None)
  - Spawns worker thread for plugin execution + detection.
  - Updates shared analysis_status.

- _apply_completed_analysis_if_needed()
  - Applies finished payload into session state once.

- _render_analysis_progress()
  - Running/completed/failed visuals and summaries.

- _render_evidence_details(evidence)
  - Styled evidence metadata panel.

- _render_hero()
- _render_evidence_loader()
  - File path input + plugin selector + Validate & Load button.
  - Clear Current gate when evidence is already loaded.

- render_home()
  - Top-level page composition.

## 12.2 ui/pages/dashboard.py

Purpose:
1. Global investigation KPIs.
2. Risk and category charts.
3. Confirmed vs review finding display separation.
4. Priority action guidance.

Function:

- render_dashboard()
  - Computes risk stats and techniques count.
  - Shows top confirmed findings and review section.
  - Priority section now falls back to review findings when confirmed list is empty.

## 12.3 ui/pages/process_analysis.py

Purpose:
1. Process tree and process detail table.
2. Suspicious process cards and cmdline drilldown.
3. Parent-child anomaly panel.

Functions:

- _has_suspicious_parent(name, ppid, pid_map)
  - Determines suspicious parent relationships using mapping list.

- render_process_analysis()
  - Builds pid/cmdline maps.
  - Highlights suspicious rows and renders finding cards.

## 12.4 ui/pages/network_analysis.py

Purpose:
1. Network KPIs, graph, connection table, suspicious cards.
2. State/PID filtering and row highlighting.

Function:

- render_network_analysis()
  - Builds DataFrame for connection details.
  - Highlights by suspicious remote IP evidence and listen-only PID set.

## 12.5 ui/pages/mitre_page.py

Purpose:
1. ATT&CK KPIs.
2. Heatmap rendering.
3. Technique table and detail expanders.

Function:

- render_mitre()
  - Uses MitreMapper outputs to populate all page sections.

## 12.6 ui/pages/timeline_page.py

Purpose:
1. Timeline KPIs and chart.
2. Event filtering and details.
3. Forensic detail formatting for memory fields.

Functions:

- _format_memory_address(value)
- _normalize_bool(value)
- _format_detail_item(key, value)
- _format_timestamp(value)
- _extract_event_timestamp(finding)
- render_timeline()

## 12.7 ui/pages/ai_chat.py

Purpose:
1. AI provider status and quick-action buttons.
2. Chat history rendering and input.
3. Suggested question shortcuts.

Functions:

- _render_chat_card(role, content)
  - Escapes user/AI text and supports minimal markdown-like formatting.

- render_ai_chat()
  - Orchestrates quick actions, chat history, and free-form prompt calls.

## 12.8 ui/pages/ioc_summary.py

Purpose:
1. IOC extraction and tabbed presentation.
2. Confirmed-vs-review distinction.
3. Plain-text export and AI IOC summary panel.

Function:

- render_ioc_summary()
  - Computes unique IOC sets.
  - Uses process_scores to sort suspicious processes by risk.
  - Sanitizes export text by replacing HTML br variants with newlines.

## 12.9 ui/pages/reports_page.py

Purpose:
1. Report type/config form.
2. Preview composition.
3. Report generation/download controls.

Functions:

- _build_preview(report_type, findings)
- render_reports()
- _md_to_html(md)

---

## 13) UI Components

## 13.1 ui/components/charts.py

Shared chart factories:

- _parse_timestamp(value)
- create_risk_donut(summary)
- create_category_bar(findings_by_cat)
- create_process_tree(processes)
- create_network_graph(connections)
- create_timeline(events)
  - Adds deterministic millisecond offsets for duplicate timestamp/category points.

- create_mitre_heatmap(tactic_data)
  - Uses merged layout dict to avoid duplicate margin argument conflicts.

## 13.2 ui/components/metrics.py

Reusable styled UI elements:

- page_header(title, subtitle="", icon="")
- risk_badge(level, large=False)
- stat_card(label, value, color="#38bdf8", icon="")
- finding_card(title, description, risk_score, category, techniques, evidence_id="", triage_status="")
  - Word-boundary truncation with ellipsis for long descriptions.
  - Unified HUMAN REVIEW REQUIRED badge rendering.

- info_banner(text, type_="info")

## 13.3 ui/styles/theme.css

Global visual system:
1. Dark forensic theme.
2. Sidebar, tabs, buttons, dataframe, input styling.
3. Custom footer and animation polish.

---

## 14) Reporting Engine (reports/report_generator.py)

Classes:

1. ForensicReportPDF(FPDF)
- Handles page chrome and section/finding rendering.

Methods:
- header(), footer()
- add_title_page(...)
- add_section_header(title)
- _safe(text)
- add_finding(...)
- add_text(text, size=10)

2. ReportGenerator

Methods:
- _normalize_report_type(report_type)
- generate(...)
- _add_executive_summary(...)
- _add_technical_analysis(...)
- _add_ioc_report(...)
- _add_mitre_report(...)

Supported report modes:
1. Executive Summary
2. Technical Analysis
3. IOC Report
4. MITRE ATT&CK Report

---

## 15) File-by-File Quick Function Index

This index lists symbols per Python file for rapid navigation.

- app.py
  - init_session_state, load_css, main

- config.py
  - _env_str, _env_int, _split_csv, _env_csv, _to_int_list
  - _normalize_supported_formats, _normalize_plugin_list, _normalize_lowercase_list
  - _normalize_ollama_url, _normalize_ai_provider
  - _normalize_windows_processes, _normalize_map_of_string_lists
  - _normalize_homoglyph_map, _normalize_risk_levels
  - _apply_environment_overrides, validate_and_normalize_config

- core/volatility_engine.py
  - EvidenceFile, PluginResult, VolatilityEngine

- core/anomaly_detector.py
  - Finding, AnomalyDetector and all _analyze/_check helpers

- core/mitre_mapper.py
  - MitreTechnique, MitreMapper

- core/ai_engine.py
  - AIEngine and provider/backoff/query helpers

- core/scenario_loader.py
  - ScenarioLoader

- ui/pages/home.py
  - _start_background_analysis, _apply_completed_analysis_if_needed, _render_analysis_progress
  - _render_evidence_details, _render_hero, _render_evidence_loader, render_home

- ui/pages/dashboard.py
  - render_dashboard

- ui/pages/process_analysis.py
  - _has_suspicious_parent, render_process_analysis

- ui/pages/network_analysis.py
  - render_network_analysis

- ui/pages/mitre_page.py
  - render_mitre

- ui/pages/timeline_page.py
  - _format_memory_address, _normalize_bool, _format_detail_item, _format_timestamp, _extract_event_timestamp, render_timeline

- ui/pages/ai_chat.py
  - _render_chat_card, render_ai_chat

- ui/pages/ioc_summary.py
  - render_ioc_summary

- ui/pages/reports_page.py
  - _build_preview, render_reports, _md_to_html

- ui/components/charts.py
  - _parse_timestamp, create_risk_donut, create_category_bar, create_process_tree
  - create_network_graph, create_timeline, create_mitre_heatmap

- ui/components/metrics.py
  - page_header, risk_badge, stat_card, finding_card, info_banner

- reports/report_generator.py
  - ForensicReportPDF, ReportGenerator

- __init__.py files (root/core/ui/ui/pages/ui/components/reports)
  - Package markers only (no functions/classes)

---

## 16) Current Operational Constraints

1. Plugin execution is sequential (no parallel scheduling).
2. Evidence hashing is synchronous and can delay initial load UX on large dumps.
3. Default analysis scope is Windows-focused.
4. AI output quality depends on provider/model availability and network.

---

## 17) Suggested Developer Validation Loop

1. Setup
- ./setup.sh

2. Run
- ./run.sh

3. Quick checks
- Python compile: python3 -m compileall -q app.py config.py core ui reports
- Deprecated cache API check: grep -rn "st.cache" .

4. UI smoke
1. Home
2. Dashboard
3. Process Analysis
4. Network Analysis
5. MITRE ATT&CK
6. Timeline
7. AI Analyst
8. IOC Summary
9. Reports

---

Prepared as a complete, current file/function behavior reference for implementation, maintenance, and paper writing.
