#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "===> Installing frontend dependencies and building React production bundle..."
cd frontend
npm install
npm run build
cd ..

echo "===> Installing backend Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

echo "===> Build completed successfully!"
