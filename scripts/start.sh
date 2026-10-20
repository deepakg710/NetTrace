#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"

echo "=========================================="
echo " NetTrace: Starting Local Toolkit (Linux)"
echo "=========================================="

# Start Backend
echo "Starting FastAPI Backend on http://127.0.0.1:8000..."
cd "$BACKEND_DIR"
"$VENV_DIR/bin/uvicorn" app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

# Start Frontend
echo "Starting React Frontend on http://127.0.0.1:5173..."
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!

echo "{"backend_pid": $BACKEND_PID, "frontend_pid": $FRONTEND_PID}" > "$PROJECT_DIR/.running_pids.json"

echo ""
echo "NetTrace is running!"
echo " - Frontend Dashboard : http://127.0.0.1:5173"
echo " - Backend API Docs   : http://127.0.0.1:8000/docs"
echo " - Health Check       : http://127.0.0.1:8000/api/v1/health"
echo ""
echo "Press Ctrl+C to terminate both servers..."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; rm -f '$PROJECT_DIR/.running_pids.json'; exit" SIGINT SIGTERM
wait
