#!/usr/bin/env bash
set -e

echo "=========================================="
echo " NetTrace Setup: Linux / macOS Environment"
echo "=========================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"

# 1. Setup Backend Virtual Environment
echo "[1/4] Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "Created virtual environment at $VENV_DIR"
else
    echo "Existing virtual environment found."
fi

# 2. Install backend dependencies
echo "[2/4] Installing backend dependencies..."
"$VENV_DIR/bin/pip" install -r "$BACKEND_DIR/requirements.txt"

# 3. Generate sample PCAPs
echo "[3/4] Generating lab sample captures..."
"$VENV_DIR/bin/python" "$PROJECT_DIR/samples/generate_samples.py"

# 4. Install frontend npm packages
echo "[4/4] Installing frontend npm packages..."
cd "$FRONTEND_DIR"
npm install

echo "=========================================="
echo " Setup Complete! Run ./scripts/start.sh"
echo "=========================================="
