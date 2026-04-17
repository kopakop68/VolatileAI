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
pip install streamlit plotly pandas numpy pyyaml fpdf2 networkx requests -q

echo "[3/3] Creating output directories..."
mkdir -p reports/output evidence idata/cached_responses idata/demo_scenarios

echo ""
echo "=== Setup Complete ==="
echo "Run: ./run.sh"
