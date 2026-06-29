#!/bin/bash
set -e

echo "================================================================="
echo "  🛡️  SuRaksha DocShield  —  Fully Offline Document Forensics"
echo "================================================================="

# FastAPI runs on a fixed internal port (not exposed publicly)
BACKEND_PORT=8000

echo "▶  Starting FastAPI backend on http://localhost:$BACKEND_PORT ..."
cd /app/backend
uvicorn main:app --host 0.0.0.0 --port $BACKEND_PORT &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"

# Wait for backend to be ready
sleep 3

echo "▶  Starting Streamlit dashboard on port $PORT ..."
cd /app
streamlit run frontend/dashboard.py \
  --server.port $PORT \
  --server.address 0.0.0.0 \
  --server.headless true \
  --browser.gatherUsageStats false

echo "================================================================="
