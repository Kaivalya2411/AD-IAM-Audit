#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  start.sh  —  Start the app (Mac / Linux)
#  Run:  bash scripts/start.sh
# ─────────────────────────────────────────────
set -e
cd "$(dirname "$0")/.."

# Activate venv if it exists
if [ -d "venv" ]; then
  source venv/bin/activate
fi

echo ""
echo "  ┌──────────────────────────────────┐"
echo "  │  AD/IAM Auditor  v2.0            │"
echo "  │  http://localhost:5000           │"
echo "  └──────────────────────────────────┘"
echo ""

python3 run.py &
APP_PID=$!
sleep 1.5

# Open browser
URL="http://localhost:5000"
if   [[ "$OSTYPE" == "darwin"* ]]; then open "$URL"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then xdg-open "$URL" 2>/dev/null || true
fi

echo "  Press Ctrl+C to stop"
wait $APP_PID
