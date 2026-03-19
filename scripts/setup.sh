#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  setup.sh  —  First-time setup (Mac / Linux)
#  Run once:  bash scripts/setup.sh
# ─────────────────────────────────────────────
set -e
cd "$(dirname "$0")/.."

echo ""
echo "  ╔══════════════════════════════════╗"
echo "  ║   AD/IAM Auditor  — Setup        ║"
echo "  ╚══════════════════════════════════╝"

# Python check
if ! command -v python3 &>/dev/null; then
  echo "  ✗ Python 3 not found. Install from https://python.org"; exit 1
fi
echo "  ✓ Python: $(python3 --version)"

# Virtual env
if [ ! -d "venv" ]; then
  echo "  → Creating virtual environment…"
  python3 -m venv venv
fi
source venv/bin/activate

# Install deps
echo "  → Installing dependencies…"
pip install -r requirements.txt -q

# Copy .env
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "  ✓ .env file created"
fi

echo ""
echo "  ✅ Setup complete!"
echo "  → Start the app:  bash scripts/start.sh"
echo ""
