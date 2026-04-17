# VolatileAI

VolatileAI is an interactive memory forensics platform that combines Volatility 3 plugin execution, heuristic anomaly detection, MITRE ATT&CK mapping, AI-assisted analysis, and PDF reporting in one Streamlit application.

## Current Status

1. Real memory-dump workflow is fully supported.
2. Multi-provider AI workflow is supported via environment variables.
3. Live runtime logs are available in terminal and saved in `logs/`.
4. Demo/cache directories are optional and can be empty.

## Key Capabilities

1. Evidence validation with hash generation (MD5/SHA-256).
2. Automated Volatility plugin execution with per-plugin progress updates.
3. Heuristic findings for process, network, injection, DLL, and persistence anomalies.
4. MITRE ATT&CK mapping and tactic/technique visual summaries.
5. Interactive process/network/timeline investigation pages.
6. AI chat assistant with Ollama, OpenAI, Anthropic, Groq, and OpenText-compatible routing.
7. Report generation (Executive, Technical, IOC, MITRE ATT&CK).

## Project Layout

```text
VolatileAI/
├── app.py
├── config.py
├── setup.sh
├── run.sh
├── core/
├── ui/
├── reports/
├── data/
│   ├── cached_responses/
│   ├── demo_scenarios/
│   └── mitre/
├── evidence/
└── logs/
```

## Quick Start

```bash
cd /home/shivam/Major/VolatileAI
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

Default app URL: `http://localhost:8502`

## Configuration

Copy environment template:

```bash
cp .env.example .env
```

Then edit `.env` with your provider settings.

Primary setting:

```bash
VOLATILEAI_AI_PROVIDER=ollama
```

Allowed providers:

1. `ollama`
2. `openai`
3. `anthropic`
4. `groq`
5. `opentext`

`run.sh` automatically loads `.env` at startup.

## Evidence Workflow

1. Open Home page.
2. Enter full path of memory dump (`.raw`, `.vmem`, `.dmp`, `.mem`, `.lime`).
3. Click Validate and Load.
4. Wait for plugin progress to complete.
5. Navigate to dashboard and analysis pages.

You can analyze multiple dumps in one running app instance using the clear/reset flow in Home page.

## Rigorous Testing Checklist

Use this before your full validation run.

1. Environment bootstrap:

```bash
./setup.sh
```

2. Verify volatility command availability:

```bash
source venv/bin/activate
vol -h >/dev/null && echo "vol OK" || echo "vol missing"
```

3. Start app with live logs:

```bash
./run.sh
```

4. In another terminal, verify bind is localhost only:

```bash
ss -ltnp | grep 8502 || true
```

5. Verify no deprecated Streamlit cache API usage:

```bash
grep -rn "st.cache" .
```

6. Validate evidence load and plugin completion in UI.

7. Confirm no runtime tracebacks in latest log:

```bash
ls -1t logs/volatileai_*.log | head -n 1
grep -n "Traceback\|ERROR\|AttributeError\|ArrowInvalid" logs/volatileai_*.log || true
```

8. Smoke test all pages:

1. Home
2. Dashboard
3. Process Analysis
4. Network Analysis
5. MITRE ATT&CK
6. Timeline
7. IOC Summary
8. AI Chat
9. Reports

9. Generate one Technical Analysis PDF and verify download/open.

10. AI checks:

1. Provider status is visible in sidebar.
2. Ask one high-confidence and one low-confidence question.
3. Confirm model avoids overconfident claims on weak evidence.

## Troubleshooting

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

3. AI not responding:

1. Check provider in `.env`.
2. Verify API key or local Ollama service.
3. Check terminal and `logs/` for network/auth errors.

4. No demo scenarios shown:

1. This is expected if `data/demo_scenarios/` is empty.
2. Add `scenario_*.json` files only if you want scenario mode.

## Security Notes

1. Keep `.env` private and never commit API keys.
2. Memory dumps can contain credentials and secrets; store evidence securely.
3. Default bind is localhost to reduce accidental exposure.

## Documentation

For complete architecture and file-level technical details, see `DOCUMENTATION.md`.
