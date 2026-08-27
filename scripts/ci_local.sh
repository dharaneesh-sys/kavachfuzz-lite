#!/usr/bin/env bash
set -euo pipefail

echo "=== KavachFuzz-Lite Local CI ==="

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "[1/4] Installing dependencies"
if [ -d .venv ]; then
    .venv/bin/pip install -e "." 2>/dev/null || true
else
    echo "No .venv found, creating..."
    python3 -m venv .venv
    .venv/bin/pip install -e "."
fi

echo "[2/4] Running tests"
.venv/bin/pytest -q

echo "[3/4] Fuzz gate (toy_crash 20s)"
.venv/bin/python -m kavach fuzz --target toy_crash --time 20

echo "[4/4] Verify crash found"
LATEST=$(ls -1d campaigns/toy_crash-* 2>/dev/null | sort | tail -1)
if [ -z "$LATEST" ]; then
    echo "FAIL: No campaign found"
    exit 1
fi
CRASHES=$(python3 -c "import json; print(json.load(open('$LATEST/stats.json'))['crashes'])")
echo "Crashes: $CRASHES"
if [ "$CRASHES" -lt 1 ]; then
    echo "FAIL: Expected ≥1 crash"
    exit 1
fi

echo "=== CI PASSED ==="
