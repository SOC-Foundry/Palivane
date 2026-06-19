#!/usr/bin/env bash
# Backend container entrypoint: wait for the DB, apply migrations, optionally seed,
# then exec the given command (uvicorn by default, or the poller).
set -euo pipefail

# Wait for Postgres to accept connections (compose healthcheck also gates this).
if [[ "${DATABASE_URL:-}" == postgresql* ]]; then
  echo "[entrypoint] waiting for database…"
  python - <<'PY'
import os, time, sys
from sqlalchemy import create_engine, text
url = os.environ["DATABASE_URL"]
for attempt in range(60):
    try:
        create_engine(url).connect().execute(text("select 1"))
        print("[entrypoint] database is up")
        sys.exit(0)
    except Exception:
        time.sleep(1)
print("[entrypoint] database did not become ready", file=sys.stderr)
sys.exit(1)
PY
fi

# Apply schema migrations (no-op if already current).
echo "[entrypoint] alembic upgrade head"
alembic upgrade head

# Optionally create the demo tenant/admin + sample findings on first boot.
if [[ "${SEED_ON_START:-false}" == "true" ]]; then
  echo "[entrypoint] seeding demo data"
  python -m app.seed || echo "[entrypoint] seed skipped/failed (continuing)"
fi

exec "$@"
