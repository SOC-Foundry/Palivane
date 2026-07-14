# Single-origin Warden image for Cloud Run: builds the React SPA and serves it from the
# FastAPI backend (SPA + /api + /v1 on one origin, no nginx). Build context = repo root:
#   gcloud builds submit --config deploy/cloudrun/cloudbuild.yaml
# syntax=docker/dockerfile:1

# --- Stage 1: build the SPA ---
FROM node:20-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build          # -> /web/dist

# --- Stage 2: backend + static SPA ---
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
RUN chmod +x docker-entrypoint.sh
COPY --from=web /web/dist ./static
# CLI + egress-proxy addon, served publicly via /install.sh and /cli/<name> for self-serve
# onboarding (see app/distribution.py).
COPY cli/ ./cli
COPY proxy/ ./proxy
ENV WARDEN_STATIC_DIR=/app/static

# Run as a non-root user — smaller blast radius if the app is compromised.
RUN useradd --system --uid 10001 warden && chown -R warden /app
USER warden

# Cloud Run injects $PORT (default 8080). The entrypoint waits for the DB, runs
# `alembic upgrade head`, then execs this CMD.
ENV PORT=8080
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
