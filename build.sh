#!/usr/bin/env bash
# Production build for a single web service (frontend bundle + backend API).
set -o errexit

echo "===> Installing frontend dependencies and building the React bundle..."
cd frontend
npm install
npm run build
cd ..

echo "===> Installing backend Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "===> Building the synthetic dataset and training the scam classifier..."
cd backend
python data/build_dataset.py
python -m app.intel.classifier --train || echo "    (classifier optional — rule engine still active)"

echo "===> Running the measured evaluation..."
python evaluate.py || echo "    (evaluation optional at build time)"
cp -f data/metrics.json ../frontend/dist/metrics.json 2>/dev/null || true

echo "===> Seeding the demo database..."
python seed_demo.py || echo "    (seed optional)"
cd ..

echo "===> Build completed successfully!"
