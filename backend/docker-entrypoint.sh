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

# Apply schema migrations.
#
# "no-op if already current" is true of the schema but NOT of the cost. migrations/env.py
# imports app.models and app.config, so `alembic upgrade head` loads the whole application
# — and then uvicorn loads it again. Every container start paid that, not just deploys,
# and on Cloud Run (4-minute startup-probe ceiling, plus a 40-60s cold Cloud SQL connect)
# it was enough to fail a rollout with the container otherwise healthy.
#
# So ask the cheap question first: is the database already at head? That needs neither the
# app nor env.py — ScriptDirectory reads the versions directory, and the current revision
# is one row. Any surprise at all (no table, a branched history with several heads, a
# failed query, an unreadable config) falls through to the real upgrade, so the safe path
# is the default and the fast path is taken only on a definite match.
skip_migrations=0
if python - <<'MIGCHECK' 2>/dev/null; then skip_migrations=1; fi
import os, sys
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

heads = set(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
if len(heads) != 1:
    sys.exit(1)                      # branched or empty history: let alembic decide
url = os.environ.get("DATABASE_URL", "")
if not url:
    sys.exit(1)
with create_engine(url).connect() as conn:
    current = {r[0] for r in conn.execute(text("select version_num from alembic_version"))}
sys.exit(0 if current == heads else 1)
MIGCHECK

if [ "$skip_migrations" = "1" ]; then
  echo "[entrypoint] database already at head, skipping alembic"
else
  echo "[entrypoint] alembic upgrade head"
  alembic upgrade head
fi

# Optionally create the demo tenant/admin + sample findings on first boot.
if [[ "${SEED_ON_START:-false}" == "true" ]]; then
  echo "[entrypoint] seeding demo data"
  python -m app.seed || echo "[entrypoint] seed skipped/failed (continuing)"
fi

exec "$@"
