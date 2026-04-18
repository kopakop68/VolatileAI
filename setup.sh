#!/bin/bash
# VolatileAI Setup Script
cd "$(dirname "$0")"
echo "=== VolatileAI Setup ==="

if [ ! -d "venv" ]; then
    echo "[1/3] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[1/3] Virtual environment exists."
fi

echo "[2/3] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt -q
else
    pip install streamlit plotly pandas numpy pyyaml fpdf2 networkx requests volatility3 -q
fi

if command -v vol >/dev/null 2>&1; then
    echo "    Volatility CLI detected: $(vol -h >/dev/null 2>&1; echo OK)"
else
    echo "    WARNING: volatility3 installed but 'vol' command was not found in PATH."
fi

echo "[3/3] Creating output directories..."
mkdir -p reports/output evidence logs

echo ""
echo "=== Setup Complete ==="
echo "Run: ./run.sh"
