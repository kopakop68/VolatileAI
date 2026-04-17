# VolatileAI — AI-Powered Memory Forensics Investigation Platform

A comprehensive memory forensics analysis tool that combines **Volatility 3** framework integration with **AI-powered analysis** for automated threat detection, anomaly identification, and investigation assistance.

## Features

- **Evidence Loader** — Load memory dumps via file path (`.raw`, `.vmem`, `.dmp`, `.mem`, `.lime`) or use built-in demo scenarios
- **Automated Analysis** — Heuristic-based anomaly detection for processes, network connections, DLLs, services, and code injection
- **Process Analysis** — Interactive process tree visualization with suspicious process highlighting
- **Network Analysis** — Network connection graph visualization with C2/beacon detection
- **MITRE ATT&CK Mapping** — Automatic mapping of findings to MITRE ATT&CK techniques with interactive heatmap
- **Forensic Timeline** — Chronological event reconstruction with risk-scored visualization
- **AI Forensic Analyst** — Chat with an AI analyst (Ollama/Phi-3 or cached responses) about findings
- **IOC Summary** — Consolidated indicator of compromise extraction and export
- **PDF Reports** — Generate Executive Summary, Technical Analysis, IOC, and MITRE ATT&CK reports

## Quick Start

```bash
cd volatile_ai

# Setup
chmod +x setup.sh run.sh
./setup.sh

# Run
./run.sh
```

Open **http://localhost:8502** in your browser.

## Demo Scenarios

Five pre-built attack scenarios with realistic synthetic Volatility output for testing:

If you remove those JSON files, the app will show no demo scenarios until you add new files to `idata/demo_scenarios/`.

| Scenario | Description |
|----------|-------------|
| **Mimikatz Credential Theft** | Spear-phishing → Word macro → Mimikatz → lateral movement |
| **Fileless Malware** | HTA → PowerShell Empire → process hollowing → WMI persistence |
| **Ransomware Deployment** | RDP brute-force → AV kill → PsExec lateral → encryption |
| **Supply Chain Rootkit** | Trojanized installer → kernel rootkit → DNS tunneling |
| **APT Multi-Stage** | Watering hole → staged payloads → credential harvest → exfiltration |

## Architecture

```
volatile_ai/
├── app.py                    # Streamlit entry point
├── config.py                 # Configuration and constants
├── core/
│   ├── volatility_engine.py  # Volatility 3 integration
│   ├── anomaly_detector.py   # Heuristic anomaly detection
│   ├── mitre_mapper.py       # MITRE ATT&CK mapping
│   ├── ai_engine.py          # AI/Ollama integration with caching
│   └── scenario_loader.py    # Demo scenario management
├── ui/
│   ├── styles/theme.css      # Dark forensics theme
│   ├── components/           # Reusable chart and metric components
│   └── pages/                # 9 analysis pages
├── idata/
│   ├── demo_scenarios/       # 5 attack scenario datasets
│   └── cached_responses/     # 118+ cached AI responses
├── reports/
│   └── report_generator.py   # PDF report generation
└── evidence/                 # Place memory dumps here
```

## Using with Real Memory Dumps

1. Place your memory dump file in any accessible directory
2. Open the app and go to "Home & Evidence"
3. Paste the full path to your dump file
4. Click "Validate & Load"
5. If Volatility 3 is installed, real plugins will run automatically

## AI Analysis

VolatileAI now supports multiple AI providers via environment variables:

- `ollama` (default)
- `openai`
- `anthropic` (Claude)
- `groq`
- `opentext` (OpenAI-compatible endpoint)

Set provider:

```bash
export VOLATILEAI_AI_PROVIDER=ollama
```

### Ollama Setup (Local)

Install Ollama and pull a small model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini
ollama serve
```

### API Provider Setup Examples

OpenAI:

```bash
export VOLATILEAI_AI_PROVIDER=openai
export OPENAI_API_KEY=your_key_here
export OPENAI_MODEL=gpt-4o-mini
```

Anthropic (Claude):

```bash
export VOLATILEAI_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY=your_key_here
export ANTHROPIC_MODEL=claude-3-5-haiku-latest
```

Groq:

```bash
export VOLATILEAI_AI_PROVIDER=groq
export GROQ_API_KEY=your_key_here
export GROQ_MODEL=llama-3.1-8b-instant
```

OpenText (OpenAI-compatible API):

```bash
export VOLATILEAI_AI_PROVIDER=opentext
export OPENTEXT_API_KEY=your_key_here
export OPENTEXT_BASE_URL=https://your-opentext-endpoint/v1
export OPENTEXT_MODEL=gpt-4o-mini
```

### Good Low-Cost / Free-Tier Friendly Models

- Local Ollama: `phi3:mini`, `qwen2.5:3b`, `llama3.2:3b`, `gemma2:2b`
- Groq (often generous free tier): `llama-3.1-8b-instant`
- OpenAI (paid, lower cost): `gpt-4o-mini`
- Anthropic (paid, lower cost): `claude-3-5-haiku-latest`

## Tech Stack

- **Streamlit** — Interactive web UI
- **Plotly** — Interactive forensic visualizations
- **Volatility 3** — Memory forensics framework
- **Ollama / Phi-3 Mini** — Local AI analysis
- **fpdf2** — PDF report generation
- **NetworkX** — Network graph analysis
- **Pandas / NumPy** — Data processing

## Requirements

- Python 3.9+
- 4GB+ RAM (8GB+ recommended with Ollama)
- macOS / Linux / Windows
- Intel or Apple Silicon Mac compatible
# VolatileAI
