# Single-origin Palivane image for Cloud Run: builds the React SPA and serves it from the
# FastAPI backend (SPA + /api + /v1 on one origin, no nginx). Build context = repo root:
#   gcloud builds submit --config deploy/cloudrun/cloudbuild.yaml
# syntax=docker/dockerfile:1

# --- Stage 1: build the SPA ---
# Base images pinned by digest (tag kept for humans/Dependabot): a tag is mutable, so the
# same commit could otherwise build a different image tomorrow. Refresh deliberately.
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS web
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
# Where the console is served, when that is a different host from the public site (the
# managed deployment: site on palivane.io, console on app.palivane.io). The SPA needs it so
# "Sign in" on a marketing page navigates to the console's origin — the session token is in
# localStorage, which is per-origin, so signing in on the site's origin would put it
# somewhere the console cannot read. Empty = single origin, which is every self-hosted
# install, and links stay relative.
ARG VITE_PALIVANE_APP_ORIGIN=""
ENV VITE_PALIVANE_APP_ORIGIN=$VITE_PALIVANE_APP_ORIGIN
RUN npm run build          # -> /web/dist

# --- Stage 2: backend + static SPA ---
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# tesseract-ocr (+ English data) for image DLP: screenshots sent through the gateway, and
# images found by the Slack/Drive/S3 connectors, are OCR'd locally (app/ocr.py) — never by
# a cloud vision API. Installed in every image, used only when PALIVANE_OCR=true, so a
# self-hosted operator turns it on with an env var rather than a rebuild. About +86 MB
# installed (~28 MB of .debs; most of it libicu and the osd data tesseract-ocr depends on).
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl \
        tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
# One thread per tesseract process. OpenMP's default (a thread per core) makes a single
# OCR ~2x slower measured, and on a shared 2-vCPU instance it would also starve the
# concurrent requests the event loop is serving.
ENV OMP_THREAD_LIMIT=1

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

# Run as a non-root user — smaller blast radius if the app is compromised. The code stays
# ROOT-owned (and so read-only to the runtime user): a compromised process must not be able
# to rewrite app/*.py, the SPA it serves, or the CLI binaries /install.sh hands to every
# endpoint. The only thing the app writes on its own disk is the SQLite fallback used when
# DATABASE_URL is unset (demo / smoke runs); that goes to /app/data, the one writable dir.
# Every real deployment sets DATABASE_URL, which overrides this ENV.
RUN useradd --system --uid 10001 --create-home palivane \
    && mkdir -p /app/data && chown palivane /app/data
ENV DATABASE_URL=sqlite:////app/data/palivane.db
USER palivane

# Cloud Run injects $PORT (default 8080). The entrypoint waits for the DB, runs
# `alembic upgrade head`, then execs this CMD.
ENV PORT=8080
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
