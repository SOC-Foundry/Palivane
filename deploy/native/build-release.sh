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
# Detector data: the ML classifier weights and the MCP reputation starter set. Omitting it
# did not fail the boot, it degraded — the service logged "classifier weights
# missing/unreadable" on every start and the affected detectors quietly did less. 2.2MB.
cp -r backend/data "$STAGE/backend/data"
cp backend/requirements.txt backend/alembic.ini backend/docker-entrypoint.sh "$STAGE/backend/"
find "$STAGE/backend" -name '__pycache__' -type d -prune -exec rm -rf {} +
cp -r frontend/dist "$STAGE/static"                 # prebuilt SPA (served single-origin)
cp -r cli "$STAGE/cli"                              # powers /install.sh + /cli endpoints
cp -r proxy "$STAGE/proxy"                          # egress-proxy addon
cp deploy/native/install.sh "$STAGE/install.sh"; chmod +x "$STAGE/install.sh"
cp deploy/palivane-api.service "$STAGE/palivane-api.service"
cp deploy/palivane.env.example "$STAGE/palivane.env.example"
# The recipient gets terms with the bytes. Without this the tarball travels with no stated
# permissions at all, which is worse for them than a restrictive licence and worse for us
# than a permissive one. cli/ and proxy/ stay Apache-2.0 — LICENSE section 5 says so.
cp LICENSE "$STAGE/LICENSE"

tar czf "$OUT/palivane-native-$TAG.tar.gz" -C "$(dirname "$STAGE")" palivane
rm -rf "$(dirname "$STAGE")"

# --- Release manifest + signature -------------------------------------------------------
# Same trust anchor as the served CLI (backend/app/release_signing.py): ECDSA P-256 over a
# canonical {name: sha256} JSON digest, verifiable with stock `openssl dgst -verify` on any
# customer box. A tarball handed over by email or a link has no TLS story once it leaves,
# so the signature is the only thing tying those bytes to a release we built.
#
# Fail-soft, mirroring the backend: no key -> unsigned manifest and a warning, so a build
# never breaks before the signing key is provisioned.
ART="$OUT/palivane-native-$TAG.tar.gz"
SHA="$(sha256sum "$ART" | cut -d" " -f1)"
MANIFEST="$OUT/palivane-native-$TAG.manifest.json"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$MANIFEST" <<JSON
{
  "artifact": {
    "name": "palivane-native-$TAG.tar.gz",
    "sha256": "$SHA"
  },
  "built": "$BUILT",
  "release": "$TAG"
}
JSON

SIG="$OUT/palivane-native-$TAG.manifest.sig"
if [ -n "${PALIVANE_RELEASE_SIGNING_KEY:-}" ]; then
  DIGEST="$(mktemp)"; KEYF="$(mktemp)"
  trap 'rm -f "$DIGEST" "$KEYF"' EXIT
  # The signed bytes are the compact sorted {name: sha256} map — the same shape
  # release_signing.py signs for the CLI, so one verification recipe covers both.
  printf '{"%s":"%s"}' "palivane-native-$TAG.tar.gz" "$SHA" > "$DIGEST"
  printf '%s' "$PALIVANE_RELEASE_SIGNING_KEY" > "$KEYF"
  openssl dgst -sha256 -sign "$KEYF" "$DIGEST" | openssl base64 -A -out "$SIG"
  echo "==> signed $SIG"
else
  rm -f "$SIG"
  echo "!! PALIVANE_RELEASE_SIGNING_KEY unset - release is UNSIGNED (manifest still written)" >&2
fi

echo "built $ART"
echo "  sha256   $SHA"
echo "  manifest $MANIFEST"
echo "Ship it, then on the target:  tar xzf palivane-native-$TAG.tar.gz && sudo ./palivane/install.sh"
