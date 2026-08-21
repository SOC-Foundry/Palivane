#!/usr/bin/env bash
# Build a self-contained Palivane release tarball for native (no-Docker) install.
#
# Run on a BUILD box that has Python + Node. Produces dist/palivane-native-<tag>.tar.gz with
# the frontend PREBUILT — so the TARGET server needs only Python 3.12+ (and Postgres for
# production). No Docker and no Node on the target. Ship the tarball, extract, run install.sh.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
TAG="$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d)"
OUT="dist"
STAGE="$(mktemp -d)/palivane"
mkdir -p "$STAGE/backend" "$OUT"

echo "==> building frontend (needs Node)"
( cd frontend && npm ci && npm run build )

echo "==> assembling release payload"
# Backend runtime only (no venv, tests, or caches).
cp -r backend/app "$STAGE/backend/app"
cp -r backend/migrations "$STAGE/backend/migrations"
cp backend/requirements.txt backend/alembic.ini backend/docker-entrypoint.sh "$STAGE/backend/"
find "$STAGE/backend" -name '__pycache__' -type d -prune -exec rm -rf {} +
cp -r frontend/dist "$STAGE/static"                 # prebuilt SPA (served single-origin)
cp -r cli "$STAGE/cli"                              # powers /install.sh + /cli endpoints
cp -r proxy "$STAGE/proxy"                          # egress-proxy addon
cp deploy/native/install.sh "$STAGE/install.sh"; chmod +x "$STAGE/install.sh"
cp deploy/palivane-api.service "$STAGE/palivane-api.service"
cp deploy/palivane.env.example "$STAGE/palivane.env.example"

tar czf "$OUT/palivane-native-$TAG.tar.gz" -C "$(dirname "$STAGE")" palivane
rm -rf "$(dirname "$STAGE")"
echo "built $OUT/palivane-native-$TAG.tar.gz"
echo "Ship it, then on the target:  tar xzf palivane-native-$TAG.tar.gz && sudo ./palivane/install.sh"
