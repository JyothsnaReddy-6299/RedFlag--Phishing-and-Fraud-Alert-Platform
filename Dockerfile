# ---------------------------------------------------------------------------
# RedFlag — single-service production image.
#
# Why Docker rather than Render's native Python runtime: the native runtime
# cannot install system packages, so Tesseract (OCR) and zbar (QR) would be
# missing and those two input modes would permanently report "degraded".
# This image installs them, so all four input modes work in production.
# ---------------------------------------------------------------------------

# --- Stage 1: build the React bundle ---------------------------------------
FROM node:20-slim AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# --- Stage 2: runtime -------------------------------------------------------
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# OCR (English + Tamil) and QR decoding.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-tam \
        libzbar0 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY backend/ ./backend/
COPY --from=frontend /build/dist ./frontend/dist

# Build the synthetic dataset, train the optional classifier, measure real
# metrics and seed the repeatable demo. Each step is non-fatal: the rule
# engine is the backbone and the app must still boot if one of them fails.
WORKDIR /app/backend
RUN python data/build_dataset.py \
 && (python -m app.intel.classifier --train || echo "classifier skipped — rules still active") \
 && (python evaluate.py || echo "evaluation skipped") \
 && (cp -f data/metrics.json ../frontend/dist/metrics.json || echo "metrics not published") \
 && (python seed_demo.py || echo "seed skipped")

EXPOSE 8000

# Render injects $PORT. Default to 8000 for local `docker run`.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
