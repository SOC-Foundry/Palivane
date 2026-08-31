# Single-origin Palivane image for Cloud Run: builds the React SPA and serves it from the
# FastAPI backend (SPA + /api + /v1 on one origin, no nginx). Build context = repo root:
#   gcloud builds submit --config deploy/cloudrun/cloudbuild.yaml
# syntax=docker/dockerfile:1

# --- Stage 1: build the SPA ---
FROM node:24-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# The /docs pages import repo markdown via ?raw ("../../../docs/*.md" from
# /web/src/components resolves to /docs) — the docs must exist in the build stage.
COPY docs/ /docs/
# Which deployment this image IS. The marketing pages make a promise about where prompt
# text goes, and the honest answer differs: self-hosted it never leaves the operator's own
# infrastructure, managed it reaches Palivane. Baked in at build time rather than fetched,
# so the page never renders one answer and then corrects itself.
#
# "1" = self-hosted, which is the STRONGER claim and therefore the one you opt into. Unset
# yields the managed copy, so a forgotten flag always understates rather than overstates.
# docker-compose sets it for the ordinary self-host path.
ARG VITE_PALIVANE_SELF_HOSTED=""
ENV VITE_PALIVANE_SELF_HOSTED=$VITE_PALIVANE_SELF_HOSTED
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
ENV PALIVANE_STATIC_DIR=/app/static

# Run as a non-root user — smaller blast radius if the app is compromised.
RUN useradd --system --uid 10001 palivane && chown -R palivane /app
USER palivane

# Cloud Run injects $PORT (default 8080). The entrypoint waits for the DB, runs
# `alembic upgrade head`, then execs this CMD.
ENV PORT=8080
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
