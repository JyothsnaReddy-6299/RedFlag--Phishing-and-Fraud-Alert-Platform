#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# RedFlag — one documented start sequence (contract "Definition of done").
#
#   ./run.sh            full setup: deps, dataset, model, seed, then serve
#   ./run.sh serve      skip setup, just run backend + frontend dev servers
#   ./run.sh seed       reset and reseed the demo database
#   ./run.sh test       run the test suite
#   ./run.sh evaluate   run the measured evaluation and publish metrics.json
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-all}"

PY=${PYTHON:-python3}

setup() {
  echo "==> Installing Python dependencies"
  $PY -m pip install --quiet --upgrade pip
  $PY -m pip install --quiet -r requirements.txt

  echo "==> Checking optional system binaries"
  command -v tesseract >/dev/null 2>&1 \
    || echo "    ! tesseract not found — screenshot OCR will report as degraded."
  echo "      (Debian/Ubuntu: sudo apt-get install -y tesseract-ocr tesseract-ocr-tam libzbar0)"

  echo "==> Building the synthetic dataset and training the classifier"
  (cd backend && $PY data/build_dataset.py && $PY -m app.intel.classifier --train)

  echo "==> Installing frontend dependencies"
  (cd frontend && npm install)
}

seed() {
  echo "==> Resetting and seeding the demo database"
  (cd backend && $PY seed_demo.py)
}

evaluate() {
  echo "==> Running the measured evaluation"
  (cd backend && $PY evaluate.py)
  cp backend/data/metrics.json frontend/public/metrics.json
  echo "    published -> frontend/public/metrics.json"
}

serve() {
  echo "==> Starting backend on :8000 and frontend on :5173"
  (cd backend && $PY -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload) &
  BACK=$!
  trap 'kill $BACK 2>/dev/null || true' EXIT
  (cd frontend && npm run dev -- --host 0.0.0.0)
}

case "$MODE" in
  all)      setup; seed; evaluate; serve ;;
  setup)    setup ;;
  seed)     seed ;;
  evaluate) evaluate ;;
  test)     $PY -m pytest -q ;;
  serve)    serve ;;
  *) echo "Usage: ./run.sh [all|setup|seed|evaluate|test|serve]"; exit 1 ;;
esac
