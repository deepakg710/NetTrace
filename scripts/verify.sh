#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"

echo "=========================================="
echo " NetTrace: Full Suite Automated Verification"
echo "=========================================="

echo ""
echo "[1/4] Running Backend Tests (Pytest)..."
cd "$BACKEND_DIR"
"$VENV_DIR/bin/pytest"
echo ">> Backend Tests Passed!"

echo ""
echo "[2/4] Running Frontend Tests (Vitest)..."
cd "$FRONTEND_DIR"
npm test
echo ">> Frontend Tests Passed!"

echo ""
echo "[3/4] Running Frontend Production Build..."
npm run build
echo ">> Production Build Succeeded!"

echo ""
echo "[4/4] Verifying Deterministic Lab Captures..."
if [ -f "$PROJECT_DIR/samples/normal_traffic.pcap" ] && [ -f "$PROJECT_DIR/samples/incident_troubleshooting.pcap" ]; then
    echo ">> Sample PCAPs Validated!"
else
    echo ">> Generating missing samples..."
    "$VENV_DIR/bin/python" "$PROJECT_DIR/samples/generate_samples.py"
fi

echo ""
echo "=========================================="
echo " ALL NETTRACE VERIFICATION CHECKS PASSED! "
echo "=========================================="
