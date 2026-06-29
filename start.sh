#!/usr/bin/env bash
# SuRaksha DocShield — Start both FastAPI backend and Streamlit dashboard

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "================================================================="
echo "  🛡️  SuRaksha DocShield  —  Fully Offline Document Forensics"
echo "================================================================="

# ── FastAPI backend ──────────────────────────────────────────────────
echo ""
echo "▶  Starting FastAPI backend on http://localhost:8000 ..."
cd "$ROOT/backend"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"

sleep 2

# ── Streamlit dashboard ──────────────────────────────────────────────
echo ""
echo "▶  Starting Streamlit dashboard on http://localhost:8501 ..."
cd "$ROOT"
streamlit run frontend/dashboard.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.fileWatcherType none &
DASHBOARD_PID=$!
echo "   Dashboard PID: $DASHBOARD_PID"

echo ""
echo "================================================================="
echo "  ✅  Both services running:"
echo "      FastAPI  → http://localhost:8000/docs"
echo "      Dashboard→ http://localhost:8501"
echo "================================================================="

# Wait for both
wait $BACKEND_PID $DASHBOARD_PID
