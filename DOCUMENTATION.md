# VolatileAI — Comprehensive Technical Documentation

> **AI-Powered Memory Forensics Investigation Platform**  
> Version 1.0.0 | Python 3.9+ | Streamlit Web UI

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Directory Structure](#3-directory-structure)
4. [Installation & Setup](#4-installation--setup)
5. [Configuration (`config.py`)](#5-configuration-configpy)
6. [Application Entry Point (`app.py`)](#6-application-entry-point-apppy)
7. [Core Modules (`core/`)](#7-core-modules-core)
   - 7.1 [Volatility Engine (`volatility_engine.py`)](#71-volatility-engine-volatility_enginepy)
   - 7.2 [Anomaly Detector (`anomaly_detector.py`)](#72-anomaly-detector-anomaly_detectorpy)
   - 7.3 [MITRE Mapper (`mitre_mapper.py`)](#73-mitre-mapper-mitre_mapperpy)
   - 7.4 [AI Engine (`ai_engine.py`)](#74-ai-engine-ai_enginepy)
   - 7.5 [Scenario Loader (`scenario_loader.py`)](#75-scenario-loader-scenario_loaderpy)
8. [UI Pages (`ui/pages/`)](#8-ui-pages-uipages)
   - 8.1 [Home & Evidence Loader (`home.py`)](#81-home--evidence-loader-homepy)
   - 8.2 [Investigation Dashboard (`dashboard.py`)](#82-investigation-dashboard-dashboardpy)
   - 8.3 [Process Analysis (`process_analysis.py`)](#83-process-analysis-process_analysispy)
   - 8.4 [Network Analysis (`network_analysis.py`)](#84-network-analysis-network_analysispy)
   - 8.5 [MITRE ATT&CK Page (`mitre_page.py`)](#85-mitre-attck-page-mitre_pagepy)
   - 8.6 [Forensic Timeline (`timeline_page.py`)](#86-forensic-timeline-timeline_pagepy)
   - 8.7 [AI Forensic Analyst (`ai_chat.py`)](#87-ai-forensic-analyst-ai_chatpy)
   - 8.8 [IOC Summary (`ioc_summary.py`)](#88-ioc-summary-ioc_summarypy)
   - 8.9 [Report Generator (`reports_page.py`)](#89-report-generator-reports_pagepy)
9. [UI Components (`ui/components/`)](#9-ui-components-uicomponents)
   - 9.1 [Charts (`charts.py`)](#91-charts-chartspy)
   - 9.2 [Metrics & Badges (`metrics.py`)](#92-metrics--badges-metricspy)
10. [UI Styles (`ui/styles/theme.css`)](#10-ui-styles-uistylesthemecss)
11. [Reports Module (`reports/`)](#11-reports-module-reports)
    - 11.1 [Report Generator (`report_generator.py`)](#111-report-generator-report_generatorpy)
12. [Data Directory (`data/`)](#12-data-directory-data)
    - 12.1 [Demo Scenarios (`data/demo_scenarios/`)](#121-demo-scenarios-datademo_scenarios)
    - 12.2 [Cached AI Responses (`data/cached_responses/`)](#122-cached-ai-responses-datacached_responses)
13. [Evidence Directory (`evidence/`)](#13-evidence-directory-evidence)
14. [Data Flow & Execution Pipeline](#14-data-flow--execution-pipeline)
15. [Session State Management](#15-session-state-management)
16. [Heuristic Detection Rules Reference](#16-heuristic-detection-rules-reference)
17. [MITRE ATT&CK Techniques Reference](#17-mitre-attck-techniques-reference)
18. [AI Analysis System](#18-ai-analysis-system)
19. [PDF Report Types](#19-pdf-report-types)
20. [Tech Stack & Dependencies](#20-tech-stack--dependencies)
21. [System Requirements](#21-system-requirements)

---

## 1. Project Overview

**VolatileAI** is a full-stack memory forensics investigation platform that bridges the gap between raw memory dump analysis and actionable threat intelligence. It integrates:

- **Volatility 3** — the industry-standard memory forensics framework — to extract process lists, network connections, DLL loads, service configurations, and code injection artifacts from memory dumps.
- **Heuristic anomaly detection** — a rule-based engine that scores and categorizes suspicious behaviors across processes, network, DLLs, services, and injections.
- **MITRE ATT&CK mapping** — automatic correlation of every finding to the MITRE ATT&CK Enterprise framework with tactic/technique metadata.
- **AI-powered analysis** — integration with Ollama (Phi-3 Mini LLM) for natural-language forensic investigation, with a 118+ entry cached response system for offline/demo use.
- **Interactive Streamlit UI** — nine specialized analysis pages with Plotly visualizations, filterable data tables, and a dark forensics theme.
- **PDF report generation** — four professional report types (Executive Summary, Technical Analysis, IOC Report, MITRE ATT&CK Report) generated via fpdf2.
- **Five demo scenarios** — pre-built synthetic Volatility output for five real-world attack patterns, enabling full platform exploration without a real memory dump.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (User)                           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP :8502
┌──────────────────────────▼──────────────────────────────────────┐
│                    Streamlit Web Server                         │
│                        app.py                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Session State                          │   │
│  │  vol_engine | detector | mitre_mapper | ai_engine       │   │
│  │  scenario_loader | findings | plugin_results            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    UI Layer                              │  │
│  │  pages/: home, dashboard, process, network, mitre,      │  │
│  │          timeline, ai_chat, ioc_summary, reports_page   │  │
│  │  components/: charts.py, metrics.py                     │  │
│  │  styles/: theme.css                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Core Layer                                 │
│                                                                 │
│  VolatilityEngine ──► subprocess(vol / python3 -m volatility3) │
│  AnomalyDetector  ──► heuristic rules ──► Finding objects      │
│  MitreMapper      ──► technique lookup ──► tactic heatmap      │
│  AIEngine         ──► Ollama HTTP API / cached JSON responses  │
│  ScenarioLoader   ──► JSON demo files ──► PluginResult objects │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      Data Layer                                 │
│                                                                 │
│  data/demo_scenarios/*.json   — synthetic Volatility output   │
│  data/cached_responses/*.json — pre-written AI answers        │
│  evidence/                    — user-supplied memory dumps      │
│  reports/output/              — generated PDF files            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Directory Structure

```
VolatileAI/
│
├── app.py                          # Streamlit entry point, routing, session init
├── config.py                       # All constants, paths, risk levels, plugin lists
├── requirements.txt                # Python package dependencies
├── setup.sh                        # One-shot setup: venv + pip + directories
├── run.sh                          # Launch script: activate venv + streamlit run
├── __init__.py                     # Package marker
├── .gitignore                      # Git ignore rules
│
├── core/                           # Business logic (no UI dependencies)
│   ├── __init__.py
│   ├── volatility_engine.py        # Volatility 3 subprocess wrapper + evidence validation
│   ├── anomaly_detector.py         # Heuristic scoring engine → Finding objects
│   ├── mitre_mapper.py             # MITRE ATT&CK technique database + mapping
│   ├── ai_engine.py                # Ollama LLM client + cache + fuzzy matching
│   └── scenario_loader.py          # Demo scenario JSON loader + timeline builder
│
├── ui/
│   ├── __init__.py
│   ├── styles/
│   │   └── theme.css               # Dark forensics CSS theme for Streamlit
│   ├── components/
│   │   ├── __init__.py
│   │   ├── charts.py               # Plotly chart factory functions
│   │   └── metrics.py              # HTML component helpers (cards, badges, banners)
│   └── pages/
│       ├── __init__.py
│       ├── home.py                 # Evidence loader + demo scenario selector
│       ├── dashboard.py            # Overview: metrics, charts, top findings, AI summary
│       ├── process_analysis.py     # Process tree + suspicious process details
│       ├── network_analysis.py     # Network graph + connection table + findings
│       ├── mitre_page.py           # MITRE heatmap + technique table + detail expanders
│       ├── timeline_page.py        # Chronological event timeline + filters
│       ├── ai_chat.py              # Chat interface with AI forensic analyst
│       ├── ioc_summary.py          # IOC extraction, tabs, export, AI IOC analysis
│       └── reports_page.py         # PDF report configuration + generation + download
│
├── reports/
│   ├── __init__.py
│   ├── report_generator.py         # ForensicReportPDF + ReportGenerator classes
│   └── output/                     # Generated PDF files (created by setup.sh)
│
├── data/
│   ├── demo_scenarios/
│   │   ├── scenario_mimikatz.json      # Spear-phishing + Mimikatz credential theft
│   │   ├── scenario_fileless.json      # HTA → PowerShell Empire → process hollowing
│   │   ├── scenario_ransomware.json    # RDP brute-force → AV kill → encryption
│   │   ├── scenario_rootkit.json       # Supply chain → kernel rootkit → DNS tunneling
│   │   └── scenario_apt.json           # APT multi-stage → exfiltration
│   └── cached_responses/
│       ├── general_qa.json             # 20+ general forensics Q&A pairs
│       ├── mimikatz_qa.json            # Mimikatz scenario-specific answers
│       ├── fileless_qa.json            # Fileless malware scenario answers
│       ├── ransomware_qa.json          # Ransomware scenario answers
│       ├── rootkit_qa.json             # Rootkit scenario answers
│       └── apt_qa.json                 # APT scenario answers
│
└── evidence/                       # Drop real memory dumps here (created by setup.sh)
```

---

## 4. Installation & Setup

### `setup.sh`

A one-shot Bash script that prepares the environment:

```bash
#!/bin/bash
cd "$(dirname "$0")"

# Step 1: Create Python virtual environment (if not already present)
python3 -m venv venv

# Step 2: Install all Python dependencies into the venv
source venv/bin/activate
pip install streamlit plotly pandas numpy pyyaml fpdf2 networkx requests

# Step 3: Create required output directories
mkdir -p reports/output evidence
```

**What it does:**
- Creates an isolated Python virtual environment in `./venv/`
- Installs all required packages (Streamlit, Plotly, Pandas, NumPy, PyYAML, fpdf2, NetworkX, Requests)
- Creates `reports/output/` for PDF storage and `evidence/` for memory dump storage

### `run.sh`

The application launcher:

```bash
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
export PYTHONPATH="$(pwd):$PYTHONPATH"
streamlit run app.py
```

**What it does:**
- Activates the virtual environment
- Sets `PYTHONPATH` to the project root so all `from core.xxx import` statements resolve correctly
- Launches Streamlit on the default port **8502**

### Quick Start

```bash
chmod +x setup.sh run.sh
./setup.sh      # One-time setup
./run.sh        # Start the app
# Open http://localhost:8502
```

### Optional: Ollama AI Setup

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini
ollama serve
# App auto-detects Ollama and switches to live AI mode
```

---

## 5. Configuration (`config.py`)

Central configuration file. All constants are imported by other modules — no hardcoded values elsewhere.

### Path Constants

| Variable | Value | Purpose |
|----------|-------|---------|
| `BASE_DIR` | `Path(__file__).parent` | Project root directory |
| `DATA_DIR` | `BASE_DIR / "data"` | Data directory |
| `MITRE_DIR` | `DATA_DIR / "mitre"` | Reserved for MITRE data files |
| `DEMO_DIR` | `DATA_DIR / "demo_scenarios"` | Demo scenario JSON files |
| `CACHE_DIR` | `DATA_DIR / "cached_responses"` | Cached AI response JSON files |
| `EVIDENCE_DIR` | `BASE_DIR / "evidence"` | Memory dump storage |
| `REPORTS_DIR` | `BASE_DIR / "reports" / "output"` | Generated PDF output |

### Application Metadata

```python
APP_NAME    = "VolatileAI"
APP_VERSION = "1.0.0"
APP_TAGLINE = "AI-Powered Memory Forensics Investigation Platform"
```

### Supported Memory Dump Formats

```python
SUPPORTED_FORMATS = [".raw", ".vmem", ".dmp", ".mem", ".lime", ".img"]
```

### Ollama Configuration (Environment-Overridable)

```python
OLLAMA_BASE_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL", "phi3:mini")
```

Override via environment variables: `OLLAMA_URL=http://remote:11434 ./run.sh`

### Risk Level Thresholds

```python
RISK_LEVELS = {
    "critical": {"color": "#ef4444", "threshold": 8.0},   # score >= 8.0
    "high":     {"color": "#f97316", "threshold": 6.0},   # score >= 6.0
    "medium":   {"color": "#eab308", "threshold": 4.0},   # score >= 4.0
    "low":      {"color": "#22c55e", "threshold": 0.0},   # score < 4.0
}
```

### Volatility Plugin Lists

**Windows plugins** (10 plugins):
`windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.dlllist`, `windows.netscan`, `windows.malfind`, `windows.handles`, `windows.svcscan`, `windows.filescan`, `windows.registry.hivelist`

**Linux plugins** (8 plugins):
`linux.pslist`, `linux.pstree`, `linux.bash`, `linux.lsof`, `linux.sockstat`, `linux.malfind`, `linux.elfs`, `linux.check_syscall`

### Windows System Process Baselines

Defines expected path, parent process, and instance count for 10 critical Windows processes:

| Process | Expected Parent | Expected Instances |
|---------|----------------|-------------------|
| `system` | `idle` | 1 |
| `smss.exe` | `system` | 1 |
| `csrss.exe` | `smss.exe` | 2 |
| `wininit.exe` | `smss.exe` | 1 |
| `winlogon.exe` | `smss.exe` | 1 |
| `services.exe` | `wininit.exe` | 1 |
| `lsass.exe` | `wininit.exe` | 1 |
| `svchost.exe` | `services.exe` | unlimited |
| `explorer.exe` | `userinit.exe` | unlimited |
| `lsaiso.exe` | `wininit.exe` | 1 |

### Suspicious Parent-Child Relationships

Defines which child processes are suspicious when spawned by specific parents:

```python
SUSPICIOUS_PARENTS = {
    "cmd.exe":        ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", ...],
    "powershell.exe": ["winword.exe", "excel.exe", "mshta.exe", "wscript.exe", ...],
    "mshta.exe":      ["winword.exe", "excel.exe", "outlook.exe"],
    "certutil.exe":   ["cmd.exe", "powershell.exe"],
    ...
}
```

### Suspicious & Known C2 Ports

```python
SUSPICIOUS_PORTS = [4444, 5555, 8888, 1337, 31337, 6666, 6667, 9001, 9050, 9051, 12345, 54321]
KNOWN_C2_PORTS   = [443, 8443, 8080, 80, 53]
```

### Homoglyph Detection Map

Unicode lookalike characters used to detect process name spoofing:

```python
HOMOGLYPH_MAP = {
    "a": ["а", "ɑ"],   # Cyrillic 'а' vs Latin 'a'
    "o": ["о", "ο"],   # Cyrillic 'о' vs Latin 'o'
    "e": ["е", "ε"],   # Cyrillic 'е' vs Latin 'e'
    # ... 10 character mappings total
}
```

---

## 6. Application Entry Point (`app.py`)

The main Streamlit application file. Handles initialization, layout, navigation, and page routing.

### `init_session_state()`

Initializes all Streamlit session state variables on first load. Uses a defaults dictionary pattern — only sets values that don't already exist (preserves state across rerenders):

| Key | Type | Purpose |
|-----|------|---------|
| `vol_engine` | `VolatilityEngine` | Volatility 3 wrapper instance |
| `detector` | `AnomalyDetector` | Heuristic analysis engine |
| `mitre_mapper` | `MitreMapper` | MITRE ATT&CK mapping engine |
| `ai_engine` | `AIEngine` | Ollama/cached AI interface |
| `scenario_loader` | `ScenarioLoader` | Demo scenario manager |
| `evidence_loaded` | `bool` | Whether evidence is currently loaded |
| `evidence_info` | `EvidenceFile \| None` | Metadata about loaded evidence |
| `current_scenario` | `str \| None` | ID of active demo scenario |
| `findings` | `List[Finding]` | All detected anomaly findings |
| `plugin_results` | `Dict[str, PluginResult]` | Raw Volatility plugin output |
| `analysis_complete` | `bool` | Whether analysis has run |
| `chat_history` | `List[Dict]` | AI chat message history |

### `load_css()`

Reads `ui/styles/theme.css` and injects it into the Streamlit page via `st.markdown()` with `unsafe_allow_html=True`. This overrides Streamlit's default styling with the dark forensics theme.

### `main()`

The primary function called on every Streamlit rerender:

1. **Page config**: Sets title to "VolatileAI", icon to 🧠, wide layout, expanded sidebar
2. **CSS injection**: Calls `load_css()`
3. **Session init**: Calls `init_session_state()`
4. **Sidebar rendering**:
   - Displays app logo, name, tagline, and version
   - Navigation radio buttons for 9 pages
   - System status indicators (Volatility availability, Ollama status, evidence loaded)
5. **Page routing**: Uses `if/elif` string matching on the selected page name to lazy-import and call the appropriate `render_*()` function

**System Status Indicators:**
- 🟢 Volatility 3: Ready (if `vol` or `python3 -m volatility3` is available)
- 🟡 Volatility 3: Demo Mode (if Volatility not installed)
- 🟢 Ollama AI: Online (if Ollama HTTP API responds)
- 🟡 Ollama AI: Cached Mode (if Ollama not running)
- 🟢 Evidence: Loaded / ⚪ Evidence: None

---

## 7. Core Modules (`core/`)

### 7.1 Volatility Engine (`volatility_engine.py`)

**Purpose:** Manages all interaction with the Volatility 3 memory forensics framework. Handles evidence validation, plugin execution, result parsing, and demo data loading.

#### Data Classes

**`EvidenceFile`** — Represents a validated memory dump file:
```python
@dataclass
class EvidenceFile:
    path: str          # Absolute file path
    filename: str      # Basename
    size_bytes: int    # File size in bytes
    size_human: str    # Human-readable size (e.g., "2.1 GB")
    format: str        # File extension (e.g., ".raw")
    md5: str           # MD5 hash of the file
    sha256: str        # SHA-256 hash of the file
    os_profile: str    # Detected OS profile (future use)
    is_valid: bool     # Whether the file passed validation
```

**`PluginResult`** — Represents the output of one Volatility plugin run:
```python
@dataclass
class PluginResult:
    plugin_name: str        # e.g., "windows.pslist"
    success: bool           # Whether the plugin ran successfully
    data: List[Dict]        # Parsed JSON rows from Volatility output
    raw_output: str         # Raw stdout from Volatility
    error: str              # Error message if failed
    row_count: int          # Number of data rows
```

#### `VolatilityEngine` Class

**`__init__()`**
- Calls `_check_volatility()` to detect if Volatility 3 is installed
- Initializes `_evidence` (current evidence file) and `_results` (plugin results cache)

**`_check_volatility() → bool`**
Tries two methods to detect Volatility 3:
1. `vol --help` (installed as a system command)
2. `python3 -m volatility3 --help` (installed as a Python module)

Returns `True` if either succeeds with exit code 0.

**`validate_evidence(file_path: str) → EvidenceFile`**
Validates a memory dump file:
1. Checks if the file exists at the given path
2. Reads file size and converts to human-readable format
3. Checks if the extension is in `SUPPORTED_FORMATS`
4. Computes MD5 and SHA-256 hashes (reads in 8KB chunks for memory efficiency)
5. Returns an `EvidenceFile` with `is_valid=True` if all checks pass

**`run_plugin(plugin_name: str, file_path: str) → PluginResult`**
Executes a single Volatility plugin:
1. Builds command: `vol -f <path> -r json <plugin_name>`
2. Falls back to: `python3 -m volatility3 -f <path> -r json <plugin_name>`
3. Timeout: 300 seconds per plugin
4. Parses JSON output into a list of dicts
5. Returns `PluginResult` with success/failure status and data

**`run_all_plugins(file_path: str, os_type: str) → Dict[str, PluginResult]`**
Runs all plugins for the detected OS type (Windows or Linux) sequentially. Returns a dict mapping plugin names to their results.

**`load_demo_results(scenario_data: Dict) → Dict[str, PluginResult]`**
Converts demo scenario JSON data into `PluginResult` objects, simulating what real Volatility execution would produce. Used when loading demo scenarios.

**`_hash_file(path, algo) → str`**
Computes cryptographic hash of a file using streaming reads (8KB chunks) to handle large memory dumps without loading them entirely into RAM.

**`_human_size(size_bytes) → str`**
Converts bytes to human-readable format (B → KB → MB → GB → TB → PB).

---

### 7.2 Anomaly Detector (`anomaly_detector.py`)

**Purpose:** The core threat detection engine. Applies heuristic rules to Volatility plugin output to identify suspicious behaviors and generate scored `Finding` objects.

#### `Finding` Data Class

```python
@dataclass
class Finding:
    category: str           # "process", "network", "dll", "injection", "persistence"
    artifact_id: str        # e.g., "PID:4688", "SVC:WindowsUpdateSvc"
    title: str              # Short human-readable title
    description: str        # Detailed description with evidence
    risk_score: float       # 0.0 – 10.0
    evidence: Dict          # Raw data row that triggered the finding
    mitre_techniques: List[str]  # e.g., ["T1059.001", "T1027"]
    timestamp: str          # Event timestamp (if available)

    @property
    def risk_level(self) -> str:
        # Returns "critical" (>=8), "high" (>=6), "medium" (>=4), or "low"
```

#### `AnomalyDetector` Class

**`analyze_all(plugin_results: Dict) → List[Finding]`**
The main entry point. Extracts data from six plugin result types and dispatches to specialized analyzers:
- `windows.pslist` + `windows.cmdline` → `_analyze_processes()`
- `windows.netscan` → `_analyze_network()`
- `windows.malfind` → `_analyze_injections()`
- `windows.dlllist` → `_analyze_dlls()`
- `windows.svcscan` → `_analyze_services()`

Results are sorted by `risk_score` descending before returning.

**`_analyze_processes(processes, cmdlines)`**
Builds a PID→process map and cmdline map, then for each process runs four checks:

1. **`_check_path_anomaly()`** — Compares the process's command line path against the expected path from `WINDOWS_SYSTEM_PROCESSES`. If a system process (e.g., `lsass.exe`) is running from outside `system32`, generates a **Critical (8.5)** finding mapped to `T1036.005`.

2. **`_check_parent_anomaly()`** — Two sub-checks:
   - If the process's parent is in `SUSPICIOUS_PARENTS` (e.g., `cmd.exe` spawned by `winword.exe`): **Critical (9.0)** finding mapped to `T1059`, `T1204.002`
   - If a known system process has an unexpected parent (e.g., `lsass.exe` not under `wininit.exe`): **High (7.0)** finding mapped to `T1036`

3. **`_check_name_spoofing()`** — Scans process names for Unicode homoglyph characters from `HOMOGLYPH_MAP`. A Cyrillic 'о' in `svchоst.exe` would trigger a **Critical (9.5)** finding mapped to `T1036.004`.

4. **`_check_suspicious_cmdline()`** — Applies 10 regex patterns to command line arguments:

| Pattern | Title | Score | MITRE |
|---------|-------|-------|-------|
| `-encodedcommand` | Encoded PowerShell command | 8.5 | T1059.001, T1027 |
| `-enc [base64]` | Base64 encoded PowerShell | 8.5 | T1059.001, T1027 |
| `downloadstring\|invoke-webrequest` | Download cradle | 8.0 | T1059.001, T1105 |
| `invoke-mimikatz\|sekurlsa\|logonpasswords` | Mimikatz keywords | 9.5 | T1003.001 |
| `net user /add\|net localgroup admin` | Account creation | 8.0 | T1136.001 |
| `vssadmin.*delete shadows` | Shadow copy deletion | 9.5 | T1490 |
| `bcdedit.*recoveryenabled.*no` | Boot recovery disabled | 9.0 | T1490 |
| `schtasks.*/create\|reg add.*\\run` | Persistence mechanism | 7.5 | T1053.005, T1547.001 |
| `certutil.*-decode\|-urlcache` | Certutil abuse | 7.5 | T1140, T1105 |
| `bitsadmin.*/transfer` | BitsAdmin transfer | 7.0 | T1197 |

Also checks for **multiple instances** of single-instance system processes (e.g., two `lsass.exe`): **High (6.5)** finding mapped to `T1036`.

**`_analyze_network(connections)`**
Processes each network connection:
- **Suspicious port connections**: If `ForeignPort` is in `SUSPICIOUS_PORTS` → **High (7.5)** finding mapped to `T1071`
- **Listening on suspicious ports**: If `LocalPort` is in `SUSPICIOUS_PORTS` and state is `LISTEN` → **High (8.0)** finding mapped to `T1571`
- **High-frequency beaconing**: Counts connections per remote IP; if ≥5 connections to same IP → **High (7.0–8.5)** finding mapped to `T1071`, `T1041`

**`_analyze_injections(malfind_data)`**
Processes each `windows.malfind` entry:
- Base score: **7.5** mapped to `T1055`
- If `PAGE_EXECUTE_READWRITE` protection: score raised to **9.0**, adds `T1055.001`
- If target is `lsass.exe`, `svchost.exe`, or `services.exe`: score +1.0 (max 10.0)

**`_analyze_dlls(dlllist_data)`**
Checks DLL load paths for suspicious locations:
- DLLs loaded from `\temp\`, `\tmp\`, `\appdata\local\temp`, or `\downloads\` → **High (6.5)** finding mapped to `T1574.001`

**`_analyze_services(svcscan_data)`**
Two checks per service:
- Service binary in suspicious path (`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`) → **High (8.0)** finding mapped to `T1543.003`
- Service binary executes `cmd` or `powershell` → **High (8.5)** finding mapped to `T1543.003`, `T1059`

**`get_risk_summary() → Dict[str, int]`**
Returns count of findings per risk level: `{"critical": N, "high": N, "medium": N, "low": N}`

**`get_findings_by_category() → Dict[str, List[Finding]]`**
Groups findings by category for chart rendering.

---

### 7.3 MITRE Mapper (`mitre_mapper.py`)

**Purpose:** Maps detected findings to MITRE ATT&CK Enterprise techniques and provides data structures for heatmap visualization.

#### `MitreTechnique` Data Class

```python
@dataclass
class MitreTechnique:
    technique_id: str   # e.g., "T1055.001"
    name: str           # e.g., "DLL Injection"
    tactic: str         # e.g., "Defense Evasion"
    description: str    # Full technique description
    detection: str      # Detection guidance
    url: str            # MITRE ATT&CK URL
```

#### Built-in Technique Database (`MITRE_TECHNIQUES`)

27 techniques are hardcoded in the module, covering all tactics relevant to memory forensics:

| Tactic | Techniques |
|--------|-----------|
| Credential Access | T1003, T1003.001 |
| Defense Evasion | T1027, T1036, T1036.004, T1036.005, T1055, T1055.001, T1055.012, T1140, T1197, T1562.001 |
| Execution | T1059, T1059.001, T1204.002 |
| Command and Control | T1071, T1105, T1571 |
| Persistence | T1053.005, T1136.001, T1543.003, T1547.001, T1574.001 |
| Exfiltration | T1041 |
| Impact | T1486, T1490 |
| Lateral Movement | T1021.002 |

#### Tactic Order

The 14 MITRE ATT&CK tactics are ordered for display:
`Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command and Control → Exfiltration → Impact`

#### `MitreMapper` Class

**`map_findings(findings) → Dict[str, List]`**
Inverts the findings list: for each finding's `mitre_techniques` list, builds a dict of `{technique_id: [findings_that_triggered_it]}`.

**`get_tactic_heatmap_data(findings) → Dict[str, List[Dict]]`**
Organizes detected techniques by tactic for the heatmap visualization. Returns:
```python
{
    "Defense Evasion": [
        {"technique_id": "T1055", "technique_name": "Process Injection",
         "count": 3, "max_severity": 9.0, "findings": [...]},
        ...
    ],
    "Credential Access": [...],
    ...
}
```

**`get_detected_techniques(findings) → List[Dict]`**
Returns a flat list of all detected techniques sorted by max severity, with full metadata (ID, name, tactic, finding count, max severity, description, detection guidance, URL).

**`get_unique_tactics(findings) → Set[str]`**
Returns the set of unique tactic names covered by the current findings.

---

### 7.4 AI Engine (`ai_engine.py`)

**Purpose:** Provides AI-powered forensic analysis through Ollama (local LLM) with an intelligent caching and fuzzy-matching fallback system.

#### `AIEngine` Class

**`__init__()`**
- Sets `_ollama_available = False` initially
- Initializes empty `_cached_responses` dict and `_context_data` string
- Calls `_load_cached_responses()` to populate cache from JSON files

**`check_ollama() → bool`**
Makes a GET request to `{OLLAMA_BASE_URL}/api/tags` with a 5-second timeout. Sets and returns `_ollama_available`. Called on every sidebar render to show live status.

**`set_context(findings_summary, plugin_data_summary)`**
Builds the system prompt for the LLM. The context includes:
- Role definition: "You are VolatileAI, an expert memory forensics analyst AI assistant"
- Analysis findings summary (top 20 findings as bullet points)
- Raw evidence data summary
- Instructions: reference specific PIDs/IPs, map to MITRE ATT&CK, provide confidence levels, suggest follow-up steps

**`ask(question, scenario_id) → str`**
The main query method. Three-tier resolution:
1. **Exact cache match**: `_make_cache_key(question, scenario_id)` → lookup in `_cached_responses`
2. **Fuzzy cache match**: `_fuzzy_match()` with Jaccard similarity ≥ 0.45
3. **Live Ollama query**: `_query_ollama()` if Ollama is available
4. **Fallback**: Returns offline mode instructions if nothing matches

**`_query_ollama(question) → str`**
POSTs to `{OLLAMA_BASE_URL}/api/generate` with:
- Model: `phi3:mini` (configurable)
- Full context prompt + user question
- Temperature: 0.3 (low for factual forensic analysis)
- Max tokens: 1024
- Timeout: 120 seconds

**`_make_cache_key(question, scenario_id) → str`**
Normalizes the question (lowercase, strip, remove trailing `?`) and prefixes with `scenario_id:` if provided. Example: `"mimikatz:what are the most suspicious processes found in memory"`

**`_fuzzy_match(question, scenario_id) → Optional[str]`**
Computes Jaccard similarity between the question's word set and each cache key's word set. Returns the best match if similarity ≥ 0.45. Respects scenario scoping — prefers scenario-specific answers over general ones.

**`_load_cached_responses()`**
Scans `CACHE_DIR` for all `*.json` files. Each file is a dict of `{question_key: answer_string}`. Keys are normalized to lowercase. Supports both string values and dict values (extracts `"response"` field).

**Convenience Methods** (all call `ask()` with preset questions):
- `get_auto_analysis(scenario_id)` — "Summarize the findings and provide an overall assessment"
- `get_attack_narrative(scenario_id)` — "Reconstruct the complete attack timeline and narrative"
- `get_ioc_list(scenario_id)` — "Generate a complete list of indicators of compromise"
- `get_recommendations(scenario_id)` — "What remediation steps and recommendations do you suggest"

---

### 7.5 Scenario Loader (`scenario_loader.py`)

**Purpose:** Loads and manages the five pre-built demo attack scenarios from JSON files.

#### `ScenarioLoader` Class

**`__init__()`**
Calls `_load_scenarios()` which scans `DEMO_DIR` for all `scenario_*.json` files and loads them into `_scenarios` dict keyed by scenario ID.

**Scenario JSON Structure:**
```json
{
  "id": "mimikatz",
  "name": "Spear-Phishing with Mimikatz Credential Theft",
  "description": "...",
  "os": "windows",
  "plugins": {
    "windows.pslist": [...],
    "windows.pstree": [...],
    "windows.cmdline": [...],
    "windows.netscan": [...],
    "windows.malfind": [...],
    "windows.dlllist": [...],
    "windows.svcscan": [...]
  }
}
```

**`list_scenarios() → List[Dict]`**
Returns a list of scenario summaries (id, name, description, os) for display in the UI.

**`get_scenario(scenario_id) → Optional[Dict]`**
Returns the full scenario dict for a given ID.

**`get_plugin_data(scenario_id) → Dict[str, List]`**
Returns the `plugins` sub-dict containing all plugin data arrays.

**`get_processes(scenario_id) → List[Dict]`**
Shortcut: returns `windows.pslist` data.

**`get_connections(scenario_id) → List[Dict]`**
Shortcut: returns `windows.netscan` data.

**`get_cmdlines(scenario_id) → List[Dict]`**
Shortcut: returns `windows.cmdline` data.

**`get_timeline_events(scenario_id, findings) → List[Dict]`**
Builds a unified chronological event list by merging:
1. Process creation events from `windows.pslist` (using `CreateTime`)
2. Network connection events from `windows.netscan` (using `Created`)
3. Finding events from the `findings` list (using `Finding.timestamp`)

All events are sorted by timestamp string. Each event has: `timestamp`, `category`, `title`, `details`, `risk_score`.

---

## 8. UI Pages (`ui/pages/`)

### 8.1 Home & Evidence Loader (`home.py`)

**Purpose:** The landing page. Provides two paths to load evidence: real memory dump files or demo scenarios.

#### `_render_hero()`
Renders the gradient title banner with the VolatileAI name, tagline, and description using inline CSS with a `linear-gradient` text effect.

#### `_load_demo_scenario(scenario_id, scenario)`
Loads a demo scenario into session state:
1. Gets plugin data from `ScenarioLoader`
2. Wraps each plugin's data in `PluginResult` objects
3. Stores in `st.session_state.plugin_results`
4. Runs `AnomalyDetector.analyze_all()` → stores findings
5. Sets `evidence_loaded = True`, `current_scenario = scenario_id`, `analysis_complete = True`
6. Builds a findings summary text and calls `ai_engine.set_context()` to prime the AI

#### `_render_evidence_loader()`
Left column of the home page:
- Text input for file path (placeholder: `/path/to/memory.raw`)
- "Validate & Load" button that:
  1. Calls `vol_engine.validate_evidence()` — shows error if invalid
  2. Displays evidence details table (filename, size, format, MD5, SHA-256)
  3. Calls `vol_engine.run_all_plugins()` with a spinner
  4. Runs anomaly detection and sets AI context
  5. Shows success banner

#### `_render_demo_scenarios()`
Right column of the home page:
- Lists all available scenarios from `ScenarioLoader.list_scenarios()`
- Each scenario shows: name, description, OS badge
- "Load Scenario" button triggers `_load_demo_scenario()`

#### `render_home()`
Main render function. Shows a success banner if evidence is already loaded, then renders the two-column layout.

---

### 8.2 Investigation Dashboard (`dashboard.py`)

**Purpose:** High-level overview of the investigation with key metrics, risk distribution charts, top findings, and an AI summary.

#### `render_dashboard()`

**Top Metrics Row (4 columns):**
| Metric | Source | Color |
|--------|--------|-------|
| Total Findings | `len(findings)` | Blue |
| Critical | `risk_summary["critical"]` | Red |
| MITRE Techniques | Unique technique IDs across all findings | Purple |
| Risk Score | Max `risk_score` across all findings | Orange |

**Charts Row (2 columns):**
- **Risk Distribution Donut** — calls `create_risk_donut(risk_summary)` — shows critical/high/medium/low proportions
- **Findings by Category Bar** — calls `create_category_bar(category_counts)` — shows count per category

**Top Critical Findings:**
- Sorted by `risk_score` descending, top 10 shown
- Each rendered as a `finding_card()` component

**AI Quick Summary:**
- Calls `ai_engine.get_auto_analysis(scenario_id)`
- Displayed in a styled dark card with `white-space: pre-wrap`

---

### 8.3 Process Analysis (`process_analysis.py`)

**Purpose:** Deep-dive into running processes with visual tree, detailed table, suspicious process findings, and parent-child relationship analysis.

#### Local `SUSPICIOUS_PARENTS` Dict
A simplified version of the config's suspicious parents, used for UI-level highlighting (defines which parents are *expected* for each process).

#### `_has_suspicious_parent(name, ppid, pid_map) → bool`
Returns `True` if the process's actual parent is NOT in the expected parents list for that process name.

#### `render_process_analysis()`

**Data Preparation:**
- Extracts `windows.pslist` and `windows.cmdline` from `plugin_results`
- Builds `pid_map` (PID → process dict) and `cmdline_map` (PID → command line string)
- Builds `process_findings` dict (artifact_id → Finding) and `risk_scores` dict

**Tab 1: 🌳 Process Tree**
- Assigns `_risk_score` to each process dict from the findings
- Calls `create_process_tree(processes)` → Plotly treemap
- Color legend: Normal (dark) / Medium (yellow) / High (orange) / Critical (red)

**Tab 2: 📋 Process Details**
- Builds a DataFrame with columns: PID, PPID, Name, Create Time, Threads, Handles
- Applies row-level styling:
  - Red background: processes with suspicious parents
  - Orange background: processes with risk score ≥ 6
- Shows styled DataFrame with dynamic height

**Suspicious Processes Section:**
- Lists all process-category findings sorted by risk score
- Each shown as `finding_card()` with command line displayed below in monospace

**Unusual Parent-Child Relationships Section:**
- Scans all processes for unexpected parent relationships
- Displays each as a red-bordered card: `child (PID X) ← spawned by parent (PID Y) ⚠ Unexpected parent`

---

### 8.4 Network Analysis (`network_analysis.py`)

**Purpose:** Visualizes network connections from memory, identifies suspicious traffic, and provides filterable connection details.

#### `render_network_analysis()`

**Top Metrics (4 columns):**
| Metric | Calculation |
|--------|-------------|
| Total Connections | `len(connections)` |
| Unique Remote IPs | Unique non-local `ForeignAddr` values |
| Suspicious | Count of network-category findings |
| Unique Ports | Unique `ForeignPort` values |

**Tab 1: 🕸️ Network Graph**
- Calls `create_network_graph(connections)` → NetworkX spring layout → Plotly scatter
- Blue nodes: local addresses; Red nodes: remote addresses
- Edges: connection lines
- Color legend shown below chart

**Tab 2: 📋 Connection Details**
- Builds DataFrame: Protocol, Local Address, Local Port, Remote Address, Remote Port, State, PID, Owner
- **Filters**: multiselect by State and by PID
- Row highlighting: red for suspicious connections, blue for ESTABLISHED
- Shows row count after filtering

**Suspicious Connections Section:**
- Lists all network-category findings sorted by risk score as `finding_card()` components

---

### 8.5 MITRE ATT&CK Page (`mitre_page.py`)

**Purpose:** Visualizes the MITRE ATT&CK coverage of detected findings with an interactive heatmap, technique table, and expandable detail cards.

#### `render_mitre()`

**Top Metrics (3 columns):**
| Metric | Source |
|--------|--------|
| Total Techniques Detected | `len(detected_techniques)` |
| Tactics Covered | Count of tactics with ≥1 technique |
| Highest Severity Technique | Name of technique with max severity |

**MITRE Heatmap:**
- Calls `create_mitre_heatmap(tactic_data)` → Plotly bubble scatter
- X-axis: tactic names; Y-axis: technique names
- Bubble size: proportional to severity score
- Color scale: green (low) → yellow → orange → red (critical)

**Detected Techniques Table:**
- DataFrame with: Technique ID, Name, Tactic, Finding Count, Max Severity (color-coded), Description (truncated to 120 chars)
- Severity column styled: Critical=red, High=orange, Medium=yellow, Low=green

**Technique Details (Expandable):**
- One `st.expander` per technique
- Shows: description, detection guidance, link to MITRE ATT&CK website, associated findings list

---

### 8.6 Forensic Timeline (`timeline_page.py`)

**Purpose:** Chronological reconstruction of attack events with risk-based filtering and visual timeline.

#### `render_timeline()`

**Event Source:**
- If `current_scenario` is set: uses `ScenarioLoader.get_timeline_events()` (merges process creation, network connections, and findings)
- Otherwise: builds events directly from findings list

**Top Metrics (3 columns):**
| Metric | Calculation |
|--------|-------------|
| Total Events | `len(events)` |
| High-Risk Events | Events with `risk_score >= 7` |
| Avg Risk Score | Mean risk score across all events |

**Timeline Chart:**
- Calls `create_timeline(events)` → Plotly scatter
- X-axis: timestamp; Y-axis: category
- Marker size: `8 + risk_score * 2` (larger = higher risk)
- Color per category: process=blue, network=purple, injection=red, dll=orange, persistence=pink

**Event Filters:**
- Category dropdown (All + each unique category)
- Minimum risk score slider (0.0 – 10.0, step 0.5)

**Event Cards:**
- Each event rendered as a styled card with:
  - Left border color based on risk level (red/orange/yellow/dark)
  - Timestamp (monospace), category badge with icon, risk score
  - Event title
  - Expandable details section (key-value pairs or code block)

**Category Icons:**
`process=⚙️`, `network=🌐`, `injection=💉`, `dll=📦`, `persistence=🔁`, `credential=🔑`, `service=🔧`

---

### 8.7 AI Forensic Analyst (`ai_chat.py`)

**Purpose:** Interactive chat interface with the AI forensic analyst. Supports quick analysis buttons, suggested questions, and free-form conversation.

#### `SUGGESTED_QUESTIONS`
10 pre-defined forensic investigation questions displayed when chat history is empty:
1. What are the most suspicious processes found in memory?
2. Are there any signs of code injection or process hollowing?
3. Which network connections look potentially malicious?
4. Summarize all indicators of compromise found so far.
5. What persistence mechanisms were detected?
6. Is there evidence of lateral movement in this memory dump?
7. What DLLs appear to be side-loaded or injected?
8. Can you correlate the findings into an attack timeline?
9. What MITRE ATT&CK techniques are represented?
10. What remediation steps do you recommend?

#### `render_ai_chat()`

**Connection Status Indicator:**
- Green dot: "Ollama connected — live analysis mode"
- Yellow dot: "Using cached analysis mode"

**Quick Analysis Buttons (4 columns):**
| Button | AI Method Called |
|--------|-----------------|
| 📋 Auto Summary | `get_auto_analysis()` |
| 📖 Attack Narrative | `get_attack_narrative()` |
| 🔎 IOC List | `get_ioc_list()` |
| 🛡️ Recommendations | `get_recommendations()` |

Each button appends both the user question and AI response to `chat_history` and calls `st.rerun()`.

**Chat History Display:**
- Uses `st.chat_message()` for proper user/assistant bubble rendering
- Renders all messages from `st.session_state.chat_history`

**Chat Input:**
- `st.chat_input("Ask about the investigation...")` at the bottom
- On submit: appends user message, calls `ai_engine.ask()`, appends response, renders both

**Suggested Questions:**
- Shown in 2-column grid when `chat_history` is empty
- Clicking any question sends it as a chat message

---

### 8.8 IOC Summary (`ioc_summary.py`)

**Purpose:** Extracts and consolidates all Indicators of Compromise from findings, organized by type with export functionality.

#### `render_ioc_summary()`

**IOC Extraction Logic:**
Iterates all findings and categorizes:
- `network` findings → extracts `ForeignAddr` (IP) and `ForeignPort`
- `process` / `injection` findings → extracts finding title as process IOC
- `persistence` findings → extracts finding title as service IOC
- All findings → extracts `mitre_techniques`

**Top Metrics (4 columns):**
| Metric | Value |
|--------|-------|
| Total IOCs | Sum of all IOC types |
| Suspicious IPs | Unique external IP addresses |
| Suspicious Processes | Unique process-related findings |
| MITRE Techniques | Unique technique IDs |

**Tabbed IOC Display (5 tabs):**

1. **🌐 IP Addresses** — Table with IP, finding title, risk score, risk level (color-coded), context description
2. **⚙️ Processes** — Table with process name, risk score, risk level (sorted by score)
3. **🔌 Network Ports** — Styled list of suspicious port numbers
4. **🔁 Services** — Styled list of suspicious service names
5. **🛡️ MITRE Techniques** — 3-column grid of technique ID badges

**Export Section:**
- Text area with formatted IOC list (copy-paste ready):
  ```
  # Suspicious IP Addresses
  185.141.27.103
  91.215.85.22
  
  # Suspicious Processes
  ...
  ```

**AI-Generated IOC Analysis:**
- Calls `ai_engine.get_ioc_list(scenario_id)` and displays in a styled dark card

---

### 8.9 Report Generator (`reports_page.py`)

**Purpose:** Configures and generates professional PDF forensic reports.

#### `REPORT_TYPES` Dictionary
Four report types with icons and descriptions:
| Type | Icon | Description |
|------|------|-------------|
| Executive Summary Report | 📊 | High-level for management |
| Technical Analysis Report | 🔬 | Deep-dive technical details |
| IOC Report | 🎯 | Focused IOC list for threat feeds |
| MITRE ATT&CK Report | 🛡️ | Framework-mapped findings |

#### `_build_preview(report_type, findings) → str`
Generates a Markdown preview string showing:
- Report type
- Finding counts by severity
- Top 5 critical findings
- MITRE techniques covered (first 10 + count of remaining)

#### `render_reports()`

**Top Metrics (3 columns):** Total Findings, Critical count, Categories count

**Two-Column Layout:**

**Left Column — Report Configuration:**
- Report type selectbox (with icon prefix)
- Description of selected report type
- Text inputs: Organization Name, Analyst Name, Case Number
- "Generate Report" button:
  1. Validates case number is provided
  2. Instantiates `ReportGenerator`
  3. Calls `generator.generate()` with all parameters
  4. Stores PDF bytes in `st.session_state["_last_pdf"]`
  5. Shows success/error banner
- "⬇️ Download PDF" button (appears after generation)

**Right Column — Report Preview:**
- Calls `_build_preview()` and renders via `_md_to_html()`
- Expandable "🤖 AI Summary Preview" section

#### `_md_to_html(md) → str`
Simple Markdown-to-HTML converter for the preview panel:
- Escapes HTML entities
- Converts `**bold**` → `<strong style='color:#38bdf8'>bold</strong>`
- Converts `_italic_` → `<em>italic</em>`
- Converts newlines to `<br>`

---

## 9. UI Components (`ui/components/`)

### 9.1 Charts (`charts.py`)

All chart functions return Plotly `go.Figure` objects. All use a shared `DARK_LAYOUT` dict for consistent dark theme styling (transparent backgrounds, Inter font, dark grid lines).

#### Color Palette

```python
COLORS = {
    "primary": "#38bdf8",    # Sky blue — main accent
    "secondary": "#818cf8",  # Indigo — secondary accent
    "success": "#22c55e",    # Green
    "warning": "#eab308",    # Yellow
    "danger": "#ef4444",     # Red
    "orange": "#f97316",     # Orange
    "cyan": "#06b6d4",       # Cyan
    "pink": "#ec4899",       # Pink
    "bg_dark": "#020617",    # Near-black background
    "bg_card": "#0f172a",    # Dark card background
    "border": "#1e293b",     # Subtle border color
}
```

#### `create_risk_donut(summary: Dict[str, int]) → go.Figure`
Creates a donut chart showing risk level distribution:
- Hole ratio: 0.65 (large center hole)
- Center annotation: total finding count
- Colors: critical=red, high=orange, medium=yellow, low=green
- Horizontal legend below chart
- Height: 320px

#### `create_category_bar(findings_by_cat: Dict[str, int]) → go.Figure`
Creates a vertical bar chart of findings per category:
- Category-specific colors: process=blue, network=purple, injection=red, dll=orange, persistence=pink, credential=yellow
- Value labels on bars
- Height: 320px

#### `create_process_tree(processes: List[Dict]) → go.Figure`
Creates a Plotly Treemap visualization of the process hierarchy:
- Root node: "System"
- Each process: node labeled `name\nPID:X`
- Parent resolution: uses `PPID` to find parent node; falls back to root if parent not in list
- Node colors based on `_risk_score` field (injected by `process_analysis.py`):
  - `>= 8`: red (#ef4444)
  - `>= 6`: orange (#f97316)
  - `>= 4`: yellow (#eab308)
  - `< 4`: dark (#334155)
- Height: 500px

#### `create_network_graph(connections: List[Dict]) → go.Figure`
Creates a force-directed network graph using NetworkX + Plotly:
1. Builds a NetworkX `Graph` with local IPs and remote IPs as nodes
2. Adds edges for each connection (local → remote)
3. Computes spring layout with `seed=42` for reproducibility, `k=2` for spacing
4. Renders as two Plotly scatter traces:
   - Edges: thin gray lines
   - Nodes: colored circles (blue=local, red=remote) with IP labels
- Height: 450px

#### `create_timeline(events: List[Dict]) → go.Figure`
Creates a scatter plot timeline:
- X-axis: timestamp strings
- Y-axis: event category (capitalized)
- Each event: one scatter trace (for individual hover text)
- Marker size: `8 + risk_score * 2` (risk-proportional)
- Colors per category: process=blue, network=purple, injection=red, dll=orange, persistence=pink, service=cyan
- Height: 350px

#### `create_mitre_heatmap(tactic_data: Dict[str, List]) → go.Figure`
Creates a bubble scatter plot for MITRE ATT&CK coverage:
- X-axis: tactic names (rotated -45°)
- Y-axis: technique names (truncated to 25 chars)
- Bubble size: `severity * 5`
- Color scale: green (0) → yellow (0.4) → orange (0.7) → red (1.0)
- Color bar labeled "Severity"
- Dynamic height: `max(400, len(techniques) * 35)`
- Empty state: annotation "No MITRE techniques detected"

---

### 9.2 Metrics & Badges (`metrics.py`)

Pure HTML/CSS component helpers that render styled elements via `st.markdown(html, unsafe_allow_html=True)`.

#### `page_header(title, subtitle, icon)`
Renders a page title with optional icon and subtitle:
- Title: 1.8rem, bold, light color
- Subtitle: 0.95rem, muted color
- Icon: 1.4em inline span

#### `risk_badge(level, large)`
Renders a colored pill badge for risk levels:
- Colors: critical=red, high=orange, medium=yellow, low=green
- Small mode: 0.8rem, 3px/10px padding
- Large mode: 1.1rem, 6px/16px padding, dot prefix (⬤)
- Rounded pill shape with matching border

#### `stat_card(label, value, color, icon)`
Renders a metric card with:
- Gradient background: `#0f172a` → `#1e293b`
- Subtle blue border
- Label: 0.75rem, uppercase, letter-spaced, muted
- Value: 1.8rem, bold, in the specified color
- Box shadow for depth

#### `finding_card(title, description, risk_score, category, techniques, evidence_id)`
Renders a finding card with:
- Left border in risk-level color
- Header row: icon + title (left) + score badge (right)
- Description text (truncated to 200 chars)
- MITRE technique badges (up to 5, monospace, blue)
- Evidence ID in small muted text
- Risk score badge format: `X.X / 10`

**Category Icons:** process=⚙️, network=🌐, injection=💉, dll=📦, persistence=🔁, credential=🔑

#### `info_banner(text, type_)`
Renders a notification banner:
- Types: `info` (blue), `success` (green), `warning` (yellow), `error` (red)
- Icons: ℹ️, ✅, ⚠️, ❌
- Flex layout with icon + text
- Subtle background tint matching the type color

---

## 10. UI Styles (`ui/styles/theme.css`)

A comprehensive CSS override file injected into Streamlit's page. Implements a **dark forensics theme** with a deep navy/slate color palette.

### Key Style Overrides

| Element | Style |
|---------|-------|
| `#MainMenu`, `footer`, `header` | Hidden (clean UI) |
| `.main .block-container` | Max-width 1300px, reduced padding |
| `stMetric` cards | Glass morphism: gradient bg, blur, blue border, hover lift |
| Sidebar | Deep gradient: `#020617` → `#0f172a` → `#1e293b`, blue right border |
| Tabs | Underline style, blue active indicator |
| Buttons | Rounded, blue border, hover lift + glow effect |
| Primary buttons | Blue gradient, white text, stronger glow on hover |
| Expanders | Dark bg, rounded, subtle border |
| Chat input | Dark bg, rounded, blue focus ring |
| DataFrames | Rounded corners, dark border |
| Text inputs | Dark bg, blue focus border |
| Scrollbars | 6px, dark track, slate thumb |

### Color Palette

| Variable | Hex | Usage |
|----------|-----|-------|
| Near-black | `#020617` | Page background |
| Dark navy | `#0f172a` | Card backgrounds |
| Slate | `#1e293b` | Borders, dividers |
| Medium slate | `#334155` | Muted borders |
| Muted text | `#64748b` | Labels, captions |
| Secondary text | `#94a3b8` | Descriptions |
| Primary text | `#e2e8f0` | Body text |
| Bright text | `#f1f5f9` | Headings |
| Sky blue | `#38bdf8` | Primary accent |

---

## 11. Reports Module (`reports/`)

### 11.1 Report Generator (`report_generator.py`)

**Purpose:** Generates professional PDF forensic reports using fpdf2.

#### `ForensicReportPDF(FPDF)` Class

Custom FPDF subclass with forensic report styling:

**`header()`** — Runs on every page:
- Dark navy header bar (15, 23, 42 RGB)
- "VolatileAI - Memory Forensics Report" in sky blue (left)
- Current datetime in muted gray (right)

**`footer()`** — Runs on every page:
- "Confidential | Page X/{nb}" centered in italic gray
- Uses `alias_nb_pages()` for total page count

**`add_title_page(report_type, org_name, analyst, case_no, scenario_name)`**
Creates the cover page:
- Large "VolatileAI" title in sky blue
- Report type subtitle
- Decorative horizontal line
- Metadata table: Organization, Analyst, Case Number, Scenario, Generated date/time

**`add_section_header(title)`**
Renders a section header:
- Dark slate fill background
- Sky blue bold text
- 5px top margin

**`add_finding(title, description, risk_score, category, techniques)`**
Renders a single finding entry:
- Risk level label + score in risk color: `[CRITICAL] 9.5/10 - Title`
- Description in muted gray (truncated to 300 chars)
- MITRE technique IDs in sky blue italic
- Horizontal separator line

**`add_text(text, size)`**
Renders body text:
- Strips Markdown formatting (`**`, `*`, `#`, `` ` ``)
- Encodes to latin-1 (PDF compatibility)
- Uses `multi_cell` for word wrapping

**`_safe(text) → str`**
Encodes text to latin-1 with replacement for PDF compatibility (handles Unicode characters that fpdf2 can't render).

#### `ReportGenerator` Class

**`generate(...) → bytes`**
Main entry point. Creates a `ForensicReportPDF`, adds title page, dispatches to the appropriate section builder, and returns PDF bytes via `io.BytesIO`.

**`_add_executive_summary(pdf, findings, ai_engine, scenario_id)`**
Sections:
1. Risk summary counts (Critical/High/Medium/Low)
2. AI-Generated Assessment (from `ai_engine.get_auto_analysis()`)
3. Top 10 Critical Findings (sorted by score)
4. Recommendations (from `ai_engine.get_recommendations()`)

**`_add_technical_analysis(pdf, findings, plugin_results, ai_engine, scenario_id)`**
Sections:
1. Attack Narrative (from `ai_engine.get_attack_narrative()`)
2. Per-category analysis sections (Process Analysis, Network Analysis, etc.)
3. All findings within each category sorted by score

**`_add_ioc_report(pdf, findings)`**
Sections:
1. Suspicious IP Addresses (extracted from network findings)
2. Suspicious Processes (from process findings)
3. MITRE ATT&CK Techniques (all unique technique IDs)

**`_add_mitre_report(pdf, findings)`**
Uses `MitreMapper.get_detected_techniques()` to get sorted technique list. For each technique:
- Technique ID + Name in sky blue
- Tactic, Description (150 chars), Detection guidance (150 chars)
- Finding count + max severity
- Auto page break when Y > 240

---

## 12. Data Directory (`data/`)

### 12.1 Demo Scenarios (`data/demo_scenarios/`)

Five pre-built attack scenarios with realistic synthetic Volatility output. Each scenario JSON contains complete plugin data that mirrors what real Volatility 3 would produce.

#### Scenario: Mimikatz Credential Theft (`scenario_mimikatz.json`)

**Attack Chain:** Spear-phishing email → Malicious Word document (`.docm`) → VBA macro → `cmd.exe` → `powershell.exe` (encoded Mimikatz) → credential dumping → lateral movement

**Key Indicators in Data:**
- `WINWORD.EXE` (PID 3284) spawns `cmd.exe` (PID 4512) — suspicious parent
- `cmd.exe` command line: `net user backdoor P@ssw0rd! /add` — account creation
- `powershell.exe` (PID 4688): `-encodedcommand SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA` — encoded Mimikatz
- `svchost.exe` (PID 5120) from `C:\Users\jsmith\AppData\Local\Temp\` — wrong path
- `malfind` entries in `lsass.exe`, `svchost.exe`, `rundll32.exe`, `powershell.exe` — `PAGE_EXECUTE_READWRITE`
- DLLs: `mimidrv.sys`, `mimilib.dll` loaded from `%TEMP%`
- Network: connection to `185.141.27.103:4444` (Metasploit default port)
- Service: `WindowsUpdateSvc` binary at `C:\Users\Public\update.exe` — suspicious path

#### Scenario: Fileless Malware (`scenario_fileless.json`)
**Attack Chain:** HTA file → PowerShell Empire → process hollowing → WMI persistence

#### Scenario: Ransomware Deployment (`scenario_ransomware.json`)
**Attack Chain:** RDP brute-force → AV kill → PsExec lateral movement → file encryption

#### Scenario: Supply Chain Rootkit (`scenario_rootkit.json`)
**Attack Chain:** Trojanized installer → kernel rootkit → DNS tunneling

#### Scenario: APT Multi-Stage (`scenario_apt.json`)
**Attack Chain:** Watering hole → staged payloads → credential harvest → data exfiltration

### 12.2 Cached AI Responses (`data/cached_responses/`)

Pre-written expert forensic analysis responses organized by scenario and question type.

#### `general_qa.json`
20+ general forensic investigation Q&A pairs covering:
- `general:summarize the findings` — Risk-weighted executive summary framework
- `general:what are the indicators of compromise` — Behavioral IOC patterns
- `general:map all findings to mitre att&ck` — Technique mapping table
- `general:what is the severity of this incident` — Severity assessment rubric
- `general:what should the incident response team do next` — IR phases (Contain/Eradicate/Recover)
- `general:what additional analysis would you recommend` — Disk, logs, network, TI recommendations
- `general:show me all suspicious processes` — Process triage methodology
- `general:what network connections are suspicious` — Network heuristics
- `general:what processes have code injection` — Injection indicators
- `general:what are the most critical findings` — Criticality ranking guidance
- And 10+ more...

#### Scenario-Specific Files
Each scenario has its own QA file (`mimikatz_qa.json`, `fileless_qa.json`, etc.) with answers tailored to that scenario's specific artifacts, PIDs, IPs, and attack chain.

**Cache Key Format:**
- General: `"general:question text normalized"`
- Scenario-specific: `"mimikatz:question text normalized"`

The `AIEngine._fuzzy_match()` method uses Jaccard similarity to find the best matching cached response even when the question wording differs slightly.

---

## 13. Evidence Directory (`evidence/`)

An empty directory created by `setup.sh` for storing real memory dump files. The application does not require files to be placed here — the evidence loader accepts any absolute path. This directory serves as a convenient default location.

**Supported formats:** `.raw`, `.vmem`, `.dmp`, `.mem`, `.lime`, `.img`

---

## 14. Data Flow & Execution Pipeline

### Loading a Demo Scenario

```
User clicks "Load Scenario" (home.py)
    │
    ▼
ScenarioLoader.get_plugin_data(scenario_id)
    │ Returns Dict[plugin_name → List[Dict]]
    ▼
Wrap each plugin's data in PluginResult objects
    │
    ▼
st.session_state.plugin_results = {plugin_name: PluginResult}
    │
    ▼
AnomalyDetector.analyze_all(plugin_results)
    │ Runs 5 analyzers (process, network, injection, dll, service)
    │ Returns List[Finding] sorted by risk_score desc
    ▼
st.session_state.findings = [Finding, ...]
    │
    ▼
AIEngine.set_context(findings_summary, scenario_name)
    │ Builds system prompt for LLM
    ▼
st.session_state.evidence_loaded = True
st.session_state.current_scenario = scenario_id
```

### Loading a Real Memory Dump

```
User enters file path + clicks "Validate & Load" (home.py)
    │
    ▼
VolatilityEngine.validate_evidence(file_path)
    │ Checks existence, extension, computes MD5/SHA-256
    │ Returns EvidenceFile
    ▼
If valid:
VolatilityEngine.run_all_plugins(file_path, os_type="windows")
    │ Runs 10 Volatility plugins via subprocess
    │ Each: vol -f <path> -r json <plugin>
    │ Returns Dict[plugin_name → PluginResult]
    ▼
AnomalyDetector.analyze_all(plugin_results)
    │ Same pipeline as demo scenario
    ▼
AIEngine.set_context(findings_summary, evidence_filename)
```

### AI Query Resolution

```
User asks question (ai_chat.py or dashboard.py)
    │
    ▼
AIEngine.ask(question, scenario_id)
    │
    ├─► Step 1: Exact cache lookup
    │   _make_cache_key(question, scenario_id)
    │   → "mimikatz:what are the most suspicious processes"
    │   → Check _cached_responses dict
    │   → Return if found
    │
    ├─► Step 2: Fuzzy cache match
    │   Jaccard similarity between question words and cache key words
    │   → Return best match if score >= 0.45
    │
    ├─► Step 3: Live Ollama query (if available)
    │   POST /api/generate with full context + question
    │   → Return LLM response
    │
    └─► Step 4: Fallback
        Return offline mode instructions
```

### PDF Report Generation

```
User configures report + clicks "Generate Report" (reports_page.py)
    │
    ▼
ReportGenerator.generate(report_type, findings, plugin_results,
                          evidence_info, org_name, analyst_name,
                          case_number, scenario_name, ai_engine, scenario_id)
    │
    ▼
ForensicReportPDF() — custom FPDF subclass
    │
    ├─► add_title_page() — cover page
    │
    ├─► Dispatch by report_type:
    │   ├─► _add_executive_summary()
    │   ├─► _add_technical_analysis()
    │   ├─► _add_ioc_report()
    │   └─► _add_mitre_report()
    │
    ▼
pdf.output(BytesIO buffer)
    │
    ▼
Return bytes → st.download_button()
```

---

## 15. Session State Management

Streamlit rerenders the entire script on every user interaction. Session state persists data across rerenders within a browser session.

### State Lifecycle

| State Key | Set When | Reset When |
|-----------|----------|------------|
| `vol_engine` | App init | Never (singleton) |
| `detector` | App init | Never (singleton) |
| `mitre_mapper` | App init | Never (singleton) |
| `ai_engine` | App init | Never (singleton) |
| `scenario_loader` | App init | Never (singleton) |
| `evidence_loaded` | Evidence/scenario loaded | New evidence loaded |
| `evidence_info` | Real evidence loaded | New evidence loaded |
| `current_scenario` | Demo scenario loaded | Real evidence loaded (set to None) |
| `findings` | Analysis complete | New analysis run |
| `plugin_results` | Analysis complete | New analysis run |
| `analysis_complete` | Analysis complete | New analysis run |
| `chat_history` | First chat message | Never (accumulates) |
| `_last_pdf` | Report generated | New report generated |
| `_last_case` | Report generated | New report generated |

### Cross-Page Data Access Pattern

All pages access shared data through `st.session_state`:
```python
# Any page can access:
findings = st.session_state.findings
plugin_results = st.session_state.plugin_results
scenario_id = st.session_state.get("current_scenario", "")
ai_engine = st.session_state.ai_engine
```

---

## 16. Heuristic Detection Rules Reference

### Process Analysis Rules

| Rule | Trigger Condition | Risk Score | MITRE |
|------|------------------|------------|-------|
| Wrong path | System process running outside expected directory | 8.5 | T1036.005 |
| Suspicious parent | Office app spawning shell/script interpreter | 9.0 | T1059, T1204.002 |
| Unexpected parent | System process with wrong parent | 7.0 | T1036 |
| Homoglyph spoofing | Unicode lookalike in process name | 9.5 | T1036.004 |
| Multiple instances | More instances than expected for system process | 6.5 | T1036 |
| Encoded PowerShell | `-encodedcommand` or `-enc [base64]` in cmdline | 8.5 | T1059.001, T1027 |
| Download cradle | `downloadstring`, `invoke-webrequest`, etc. | 8.0 | T1059.001, T1105 |
| Mimikatz keywords | `invoke-mimikatz`, `sekurlsa`, `logonpasswords` | 9.5 | T1003.001 |
| Account creation | `net user /add`, `net localgroup admin` | 8.0 | T1136.001 |
| Shadow copy deletion | `vssadmin delete shadows` | 9.5 | T1490 |
| Boot recovery disabled | `bcdedit recoveryenabled no` | 9.0 | T1490 |
| Persistence mechanism | `schtasks /create`, `reg add \run` | 7.5 | T1053.005, T1547.001 |
| Certutil abuse | `certutil -decode`, `certutil -urlcache` | 7.5 | T1140, T1105 |
| BitsAdmin transfer | `bitsadmin /transfer` | 7.0 | T1197 |

### Network Analysis Rules

| Rule | Trigger Condition | Risk Score | MITRE |
|------|------------------|------------|-------|
| Suspicious port connection | Remote port in SUSPICIOUS_PORTS list | 7.5 | T1071 |
| Listening on suspicious port | Local port in SUSPICIOUS_PORTS + LISTEN state | 8.0 | T1571 |
| High-frequency beaconing | ≥5 connections to same remote IP | 7.0–8.5 | T1071, T1041 |

### Injection Analysis Rules

| Rule | Trigger Condition | Risk Score | MITRE |
|------|------------------|------------|-------|
| Code injection | Any malfind entry | 7.5 | T1055 |
| RWX injection | `PAGE_EXECUTE_READWRITE` protection | 9.0 | T1055, T1055.001 |
| Critical process injection | Target is lsass/svchost/services | +1.0 (max 10) | T1055 |

### DLL Analysis Rules

| Rule | Trigger Condition | Risk Score | MITRE |
|------|------------------|------------|-------|
| Suspicious DLL path | DLL loaded from temp/downloads directory | 6.5 | T1574.001 |

### Service Analysis Rules

| Rule | Trigger Condition | Risk Score | MITRE |
|------|------------------|------------|-------|
| Suspicious service path | Binary in temp/appdata/public directory | 8.0 | T1543.003 |
| Script interpreter service | Service executes cmd.exe or powershell.exe | 8.5 | T1543.003, T1059 |

---

## 17. MITRE ATT&CK Techniques Reference

All 27 techniques built into `mitre_mapper.py`:

| ID | Name | Tactic |
|----|------|--------|
| T1003 | OS Credential Dumping | Credential Access |
| T1003.001 | LSASS Memory | Credential Access |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |
| T1036.004 | Masquerade Task or Service | Defense Evasion |
| T1036.005 | Match Legitimate Name or Location | Defense Evasion |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1053.005 | Scheduled Task | Persistence |
| T1055 | Process Injection | Defense Evasion |
| T1055.001 | DLL Injection | Defense Evasion |
| T1055.012 | Process Hollowing | Defense Evasion |
| T1059 | Command and Scripting Interpreter | Execution |
| T1059.001 | PowerShell | Execution |
| T1071 | Application Layer Protocol | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1136.001 | Local Account | Persistence |
| T1140 | Deobfuscate/Decode Files | Defense Evasion |
| T1197 | BITS Jobs | Defense Evasion |
| T1204.002 | Malicious File | Execution |
| T1486 | Data Encrypted for Impact | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1543.003 | Windows Service | Persistence |
| T1547.001 | Registry Run Keys | Persistence |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1571 | Non-Standard Port | Command and Control |
| T1574.001 | DLL Search Order Hijacking | Persistence |

---

## 18. AI Analysis System

### Architecture

```
User Question
    │
    ▼
AIEngine.ask(question, scenario_id)
    │
    ├── Cache Key: "{scenario_id}:{normalized_question}"
    │
    ├── Tier 1: Exact Match
    │   └── O(1) dict lookup in _cached_responses
    │
    ├── Tier 2: Fuzzy Match (Jaccard Similarity)
    │   ├── Tokenize question into word set
    │   ├── For each cache key: compute |intersection| / |union|
    │   ├── Threshold: 0.45 (45% word overlap)
    │   └── Prefer scenario-specific over general answers
    │
    ├── Tier 3: Live Ollama (phi3:mini)
    │   ├── System prompt: role + findings context + evidence data
    │   ├── Temperature: 0.3 (factual, low creativity)
    │   ├── Max tokens: 1024
    │   └── Timeout: 120 seconds
    │
    └── Tier 4: Offline Fallback
        └── Instructions to install Ollama
```

### Context Injection

When evidence is loaded, `set_context()` builds a system prompt containing:
```
You are VolatileAI, an expert memory forensics analyst AI assistant.
You are analyzing a memory dump and have the following evidence:

=== ANALYSIS FINDINGS ===
- [CRITICAL] Encoded PowerShell command: powershell.exe -encodedcommand...
- [HIGH] Connection to suspicious port 4444: svchost.exe → 185.141.27.103:4444
...

=== RAW EVIDENCE DATA ===
Scenario: Spear-Phishing with Mimikatz Credential Theft

When answering questions:
- Reference specific PIDs, process names, IP addresses...
- Map findings to MITRE ATT&CK techniques...
- Provide confidence levels...
- Suggest follow-up investigation steps...
```

### Cached Response System

The cache covers 6 JSON files with 118+ pre-written expert responses:
- **`general_qa.json`**: 20 general forensic methodology questions
- **`mimikatz_qa.json`**: Mimikatz scenario-specific analysis
- **`fileless_qa.json`**: Fileless malware scenario analysis
- **`ransomware_qa.json`**: Ransomware scenario analysis
- **`rootkit_qa.json`**: Rootkit scenario analysis
- **`apt_qa.json`**: APT scenario analysis

All responses are written at expert forensic analyst level, referencing MITRE ATT&CK techniques, providing confidence levels, and suggesting follow-up actions.

---

## 19. PDF Report Types

### Executive Summary Report
**Audience:** Management, CISO, non-technical stakeholders  
**Sections:**
1. Risk summary (Critical/High/Medium/Low counts)
2. AI-Generated Assessment (narrative overview)
3. Top 10 Critical Findings (with scores and MITRE IDs)
4. Recommendations (AI-generated remediation steps)

### Technical Analysis Report
**Audience:** Security analysts, incident responders  
**Sections:**
1. Attack Narrative (AI-generated attack chain reconstruction)
2. Per-category analysis (Process, Network, Injection, DLL, Persistence)
3. All findings within each category with full details

### IOC Report
**Audience:** Threat intelligence teams, SOC analysts  
**Sections:**
1. Suspicious IP Addresses (extracted from network findings)
2. Suspicious Processes (from process/injection findings)
3. MITRE ATT&CK Techniques (all unique technique IDs)

### MITRE ATT&CK Report
**Audience:** Detection engineers, purple team  
**Sections:**
- One entry per detected technique with:
  - Technique ID + Name
  - Tactic
  - Description (150 chars)
  - Detection guidance (150 chars)
  - Finding count + max severity score

---

## 20. Tech Stack & Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `streamlit` | ≥1.28.0 | Web UI framework, session state, page routing |
| `plotly` | ≥5.18.0 | Interactive charts (donut, bar, treemap, scatter, network) |
| `pandas` | ≥1.3.0 | DataFrame creation and styling for data tables |
| `numpy` | ≥1.21.0 | Numerical operations (used by Plotly/Pandas) |
| `pyyaml` | ≥6.0 | YAML parsing (available for config extensions) |
| `fpdf2` | ≥2.7.0 | PDF generation for forensic reports |
| `networkx` | ≥2.6 | Network graph layout computation (spring layout) |
| `requests` | ≥2.28.0 | HTTP client for Ollama API communication |
| `volatility3` | ≥2.5.0 | Memory forensics framework (optional, enables live analysis) |
| `chromadb` | ≥0.4.0 | Vector database (available for RAG extensions) |
| `sentence-transformers` | ≥2.2.0 | Text embeddings (available for semantic search) |

**Standard Library Used:** `subprocess`, `json`, `hashlib`, `os`, `pathlib`, `re`, `io`, `datetime`, `dataclasses`, `typing`

---

## 21. System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.9 | 3.11+ |
| RAM | 4 GB | 8 GB+ (16 GB with Ollama) |
| Disk | 500 MB | 2 GB+ (for memory dumps) |
| OS | Linux / macOS / Windows | Linux / macOS |
| CPU | Any x86-64 | Multi-core for Volatility |
| Network | Not required | For Ollama API |

### Optional Components

| Component | Purpose | Install |
|-----------|---------|---------|
| Volatility 3 | Live memory dump analysis | `pip install volatility3` |
| Ollama | Local LLM for live AI analysis | `curl -fsSL https://ollama.com/install.sh \| sh` |
| Phi-3 Mini model | AI model (3.8B parameters) | `ollama pull phi3:mini` |

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `phi3:mini` | LLM model to use |

---

*Documentation generated for VolatileAI v1.0.0*  
*Repository: https://github.com/kopakop68/VolatileAI*
