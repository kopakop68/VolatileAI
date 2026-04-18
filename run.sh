#!/bin/bash
# VolatileAI Launch Script
set -e

cd "$(dirname "$0")"
source venv/bin/activate
export PYTHONPATH="$(pwd):$PYTHONPATH"
export PYTHONUNBUFFERED=1

# Load environment variables from .env if present.
if [ -f ".env" ]; then
	set -a
	# shellcheck disable=SC1091
	source .env
	set +a
fi

# Streamlit app logs.
mkdir -p logs
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
LOG_FILE="logs/volatileai_${TIMESTAMP}.log"

# Safer defaults: bind only to localhost unless explicitly overridden.
STREAMLIT_HOST="${STREAMLIT_HOST:-127.0.0.1}"
STREAMLIT_PORT="${STREAMLIT_PORT:-8502}"

echo ""
echo "  VolatileAI — AI-Powered Memory Forensics"
echo "  ─────────────────────────────────────────────"
echo "  Open http://localhost:${STREAMLIT_PORT} in your browser"
echo "  Streamlit bind address: ${STREAMLIT_HOST}"
echo "  Logging to: ${LOG_FILE}"
echo ""

# Use line-buffered output so logs appear live in terminal while being saved.
stdbuf -oL -eL streamlit run app.py \
	--server.address "${STREAMLIT_HOST}" \
	--server.port "${STREAMLIT_PORT}" \
	2>&1 | tee -a "${LOG_FILE}"
