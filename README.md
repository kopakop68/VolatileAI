# VolatileAI

VolatileAI is an AI-assisted memory forensics investigation platform that turns raw Volatility plugin output into analyst-ready findings, MITRE ATT&CK context, and report artifacts.

It is designed for Windows memory incident-response workflows where analysts need:
1. Fast triage from a real memory dump file.
2. Explainable rule-based detection (not black-box scoring only).
3. Structured attack-context mapping and reporting.
4. Optional AI assistance for narrative and recommendations.

---

## 1) Abstract (Paper-Friendly)

VolatileAI combines deterministic memory-forensics heuristics with interactive visualization and large-language-model assistance in a single analyst workspace. The platform executes a configurable Volatility 3 plugin set, fuses process/network/injection/service artifacts into a unified finding model, maps evidence to MITRE ATT&CK, and exports stakeholder-oriented PDF reports. The architecture emphasizes practical analyst usability (progress feedback, in-session re-analysis, page-level drilldowns) and operational safety (localhost binding, environment-driven provider credentials).

---

## 2) Problem Statement

Raw memory forensics output is high-value but fragmented. Analysts typically spend significant time correlating:
1. Process trees and parent-child anomalies.
2. Network socket state and endpoint patterns.
3. Injection evidence from malfind.
4. ATT&CK technique alignment.
5. Human-readable report generation.

VolatileAI addresses this by converting plugin rows into a normalized, scored finding pipeline with UI and report surfaces built around real investigation tasks.

---

## 3) Core Contributions

1. Deterministic finding engine with category-specific heuristics and risk scoring.
2. Plugin execution orchestration with per-plugin progress and ETA.
3. Endpoint-level network deduplication and false-positive controls.
4. ATT&CK tactic-technique summaries and heatmap visualizations.
5. Multi-provider AI routing with offline-safe behavior and rate-limit backoff for live providers.
6. In-app report generation for executive and technical audiences.

---

## 4) System Architecture

High-level layers:
1. Presentation Layer: Streamlit pages and reusable components.
2. Analysis Layer: Volatility wrapper, anomaly detector, MITRE mapper.
3. AI Layer: Provider routing and context-constrained responses.
4. Reporting Layer: FPDF report generation.
5. Runtime Layer: setup and launch scripts, logs, environment config.

Execution flow:
1. User starts app via run.sh.
2. Home page validates evidence and selected plugins.
3. Background worker executes plugins and updates progress state.
4. Detector builds Finding objects from plugin output.
5. Mapper derives ATT&CK summaries.
6. Pages render findings, charts, and export surfaces.
7. Report module produces downloadable PDF.

---

## 5) Current Feature Set

1. Real memory-dump validation and hashing (MD5/SHA-256).
2. Configurable plugin execution with preset-based plugin selector.
3. Process, network, injection, DLL, and persistence heuristic detections.
4. MITRE ATT&CK table plus tactic/technique heatmap.
5. Timeline and graph-based forensic visualization.
6. AI Analyst page with quick actions and free-form Q&A.
7. IOC extraction and plaintext export.
8. Four report types:
	1. Executive Summary
	2. Technical Analysis
	3. IOC Report
	4. MITRE ATT&CK Report

---

## 6) Repository Layout

```text
VolatileAI/
├── app.py
├── config.py
├── run.sh
├── setup.sh
├── requirements.txt
├── README.md
├── DOCUMENTATION.md
├── .env.example
├── .streamlit/config.toml
├── core/
│   ├── ai_engine.py
│   ├── anomaly_detector.py
│   ├── mitre_mapper.py
│   ├── scenario_loader.py
│   └── volatility_engine.py
├── ui/
│   ├── components/
│   │   ├── charts.py
│   │   └── metrics.py
│   ├── pages/
│   │   ├── home.py
│   │   ├── dashboard.py
│   │   ├── process_analysis.py
│   │   ├── network_analysis.py
│   │   ├── mitre_page.py
│   │   ├── timeline_page.py
│   │   ├── ai_chat.py
│   │   ├── ioc_summary.py
│   │   └── reports_page.py
│   └── styles/theme.css
├── reports/
│   ├── report_generator.py
│   └── output/
├── evidence/
└── logs/
```

For a complete file-by-file behavior reference, see DOCUMENTATION.md.

---

## 7) Quick Start

```bash
cd /home/shivam/Major/VolatileAI
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

Default app URL: http://localhost:8502

---

## 8) Configuration

Create local runtime config:

```bash
cp .env.example .env
```

Primary runtime provider switch:

```bash
VOLATILEAI_AI_PROVIDER=ollama
```

Allowed values:
1. ollama
2. openai
3. anthropic
4. groq
5. opentext

The launcher automatically loads .env.

---

## 9) Evidence and Analysis Workflow

1. Open Home page.
2. Enter absolute memory dump path.
3. Select plugin profile:
	1. Quick Triage
	2. Full Analysis
	3. Network Focus
	4. Injection Focus
	5. Custom
4. Click Validate & Load.
5. Wait for plugin progress and completion summary.
6. Investigate findings across Dashboard, Process, Network, MITRE, Timeline, IOC, AI, and Reports pages.

You can run multiple analyses in one app session using Clear Current.

---

## 10) Methodology (For Paper Writing)

### 10.1 Data Acquisition

Volatility plugins are executed sequentially on the memory image. Results are captured as structured JSON row arrays and normalized into PluginResult objects.

### 10.2 Detection Logic

Heuristic rules evaluate:
1. Process relationships and expected parent/path baselines.
2. Suspicious interpreter and command-line patterns.
3. Network indicators (endpoint deduplication, suspicious/listening ports, beaconing frequency).
4. Injection signals from malfind output.
5. DLL and service path anomalies.

### 10.3 Risk Scoring and Triage

Each finding receives:
1. Risk score (0 to 10).
2. Risk level band (critical/high/medium/low).
3. Triage status (malicious/review/informational semantics where applicable).

### 10.4 ATT&CK Mapping

Findings carry MITRE IDs that are grouped by technique and tactic for:
1. KPI computation.
2. Heatmap/table rendering.
3. ATT&CK report generation.

### 10.5 AI Assistance

The AI layer receives constrained context:
1. Findings summary.
2. Plugin evidence summary.
3. Confirmed ATT&CK ID list.

Provider routes support offline-safe fallback messaging and transient/rate-limit backoff for live API calls.

---

## 11) Evaluation Plan You Can Use in a Paper

### 11.1 Detection Utility

1. Use labeled or manually validated memory cases.
2. Measure precision-like behavior over top-N findings.
3. Track false-positive changes after rule tuning.

### 11.2 Analyst Efficiency

1. Time-to-triage: raw Volatility workflow vs VolatileAI workflow.
2. Time-to-report: manual report drafting vs built-in PDF export.
3. Number of manual correlation steps per case.

### 11.3 Explainability

Assess whether each finding includes:
1. Artifact specificity (PID/IP/path/cmdline).
2. ATT&CK context.
3. Confidence-appropriate language in AI output.

### 11.4 Suggested Quantitative Metrics

1. Mean triage time per case.
2. Finding precision at top 5 and top 10.
3. Report generation time.
4. ATT&CK coverage count (techniques/tactics).
5. Reviewer agreement score for AI narrative correctness.

---

## 12) Reproducibility Checklist

1. Bootstrap environment:

```bash
./setup.sh
```

2. Verify Volatility command path:

```bash
source venv/bin/activate
vol -h >/dev/null && echo "vol OK" || echo "vol missing"
```

3. Start app:

```bash
./run.sh
```

4. Verify localhost-only bind:

```bash
ss -ltnp | grep 8502 || true
```

5. Validate no deprecated cache API usage:

```bash
grep -rn "st.cache" .
```

6. Run compile sanity:

```bash
source venv/bin/activate
python3 -m compileall -q app.py config.py core ui reports
```

7. UI smoke-test all nine pages and generate one technical PDF.

8. Archive logs from logs directory for experiment traceability.

---

## 13) Security and Operational Notes

1. Keep .env private; never commit secrets.
2. Memory dumps can contain credentials and sensitive host data.
3. Default localhost bind reduces accidental exposure.
4. Generated reports should be handled as confidential artifacts.

---

## 14) Known Limitations (v1.0)

1. Suspicious ports list may include 8888 by default; tune VOLATILEAI_SUSPICIOUS_PORTS for developer workstation images.
2. Evidence hash generation is synchronous and may delay UX on very large dumps.
3. This release is Windows-memory focused by design.
4. Plugin execution is sequential (no parallel scheduling).
5. ATT&CK catalog is static in code and not auto-synced from upstream ATT&CK releases.

---

## 15) Troubleshooting

1. App does not start:

```bash
source venv/bin/activate
pip install -r requirements.txt
./run.sh
```

2. Volatility command missing:

```bash
source venv/bin/activate
pip install volatility3
python3 -m volatility3 -h | head
```

3. AI provider unavailable:
1. Check provider value in .env.
2. Confirm API key and base URL.
3. For Ollama, verify service and model availability.
4. Review logs for auth/network/rate-limit errors.

---

## 16) Citation / Project Description Snippet

Use this short paragraph in reports or paper appendices:

VolatileAI is a Streamlit-based memory forensics platform that integrates Volatility 3 plugin orchestration, deterministic anomaly detection, MITRE ATT&CK mapping, AI-assisted investigative analysis, and PDF report generation. It is optimized for Windows memory incident-response workflows and emphasizes explainability, reproducibility, and analyst productivity.

---

## 17) Additional Technical Reference

For full function-by-function and file-by-file internals, see DOCUMENTATION.md.
