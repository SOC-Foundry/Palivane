#!/usr/bin/env bash
# Palivane native installer — run Palivane directly on a server, NO Docker.
#
# Run as root on the TARGET server from an extracted release tarball (built by
# build-release.sh). The target needs only Python 3.12-3.14 (and Postgres for production; the
# default is a local SQLite file). Sets up a system user, a venv, /etc/palivane/palivane.env,
# runs migrations, and installs + starts the systemd service.
#
#   sudo ./install.sh
set -euo pipefail

PREFIX="${PALIVANE_PREFIX:-/opt/palivane}"
DATADIR="${PALIVANE_DATADIR:-/var/lib/palivane}"
ENVDIR=/etc/palivane
ENVFILE="$ENVDIR/palivane.env"
SVCUSER=palivane
SRC="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "run as root: sudo ./install.sh" >&2; exit 1; }
# The interpreter for the venv: PALIVANE_PYTHON, else the first of these that is a version the
# dependencies ship wheels for (3.12-3.14). A distro's default python3 can run ahead of that
# (Fedora's moved to 3.15 in Nov 2026, and psycopg2-binary then has to build from source and
# fails without pg_config), so a supported versioned interpreter beside it is preferred.
PY_MIN=312 PY_MAX=314
py_ver() { "$1" -c 'import sys;print("%d%02d"%sys.version_info[:2])' 2>/dev/null; }
PY="${PALIVANE_PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3.14 python3.13 python3.12 python3; do
    command -v "$c" >/dev/null 2>&1 || continue
    v="$(py_ver "$c" || true)"
    if [ -n "$v" ] && [ "$v" -ge "$PY_MIN" ] && [ "$v" -le "$PY_MAX" ]; then PY="$c"; break; fi
  done
fi
if [ -z "$PY" ]; then
  found="$(python3 -V 2>/dev/null || echo "no python3")"
  echo "Python 3.12-3.14 is required (found: $found). Install a supported one beside it, e.g." >&2
  echo "  dnf install python3.14   |   apt-get install python3.12 python3.12-venv" >&2
  echo "or point PALIVANE_PYTHON at an interpreter to use." >&2
  exit 1
fi
command -v "$PY" >/dev/null 2>&1 || { echo "PALIVANE_PYTHON=$PY is not runnable" >&2; exit 1; }
echo "==> using $PY ($("$PY" -V 2>&1))"
for f in backend static palivane-api.service palivane.env.example; do
  [ -e "$SRC/$f" ] || { echo "missing $f — run this from an extracted release tarball" >&2; exit 1; }
done

echo "==> service user + directories"
id "$SVCUSER" >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin "$SVCUSER"
mkdir -p "$PREFIX" "$DATADIR" "$ENVDIR"

echo "==> install payload to $PREFIX"
rm -rf "$PREFIX/backend" "$PREFIX/static" "$PREFIX/cli" "$PREFIX/proxy"
cp -r "$SRC/backend" "$PREFIX/backend"
cp -r "$SRC/static" "$PREFIX/static"
[ -d "$SRC/cli" ] && cp -r "$SRC/cli" "$PREFIX/cli"       # powers /install.sh + /cli endpoints
[ -d "$SRC/proxy" ] && cp -r "$SRC/proxy" "$PREFIX/proxy"

echo "==> python venv + dependencies"
"$PY" -m venv "$PREFIX/backend/.venv"
"$PREFIX/backend/.venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/backend/.venv/bin/pip" install --quiet -r "$PREFIX/backend/requirements.txt"

echo "==> environment file"
if [ ! -f "$ENVFILE" ]; then
  install -m 600 "$SRC/palivane.env.example" "$ENVFILE"
  sed -i "s#replace-me-with-a-long-random-secret#$(openssl rand -hex 32)#" "$ENVFILE"
  sed -i "s#^DATABASE_URL=.*#DATABASE_URL=sqlite:///$DATADIR/palivane.db#" "$ENVFILE"
  grep -q '^PALIVANE_STATIC_DIR=' "$ENVFILE" || echo "PALIVANE_STATIC_DIR=$PREFIX/static" >> "$ENVFILE"
  echo "   wrote $ENVFILE — EDIT IT: point DATABASE_URL at your Postgres for production."
else
  # Upgrade from a pre-rename install: the app reads PALIVANE_* only, so migrate any
  # legacy PALIVANE_* names in place (values untouched — sessions and encryption keys survive).
  if grep -q '^PALIVANE_' "$ENVFILE"; then
    sed -i 's/^PALIVANE_/PALIVANE_/' "$ENVFILE"
    echo "   $ENVFILE: renamed legacy PALIVANE_* vars to PALIVANE_* (values unchanged)."
  else
    echo "   $ENVFILE exists — leaving it untouched."
  fi
fi

chown -R "$SVCUSER:$SVCUSER" "$PREFIX" "$DATADIR" "$ENVDIR"

echo "==> database migrations"
( cd "$PREFIX/backend"
  set -a; . "$ENVFILE"; set +a
  sudo -u "$SVCUSER" env DATABASE_URL="$DATABASE_URL" PALIVANE_SECRET_KEY="$PALIVANE_SECRET_KEY" \
    "$PREFIX/backend/.venv/bin/alembic" upgrade head )

echo "==> systemd service"
install -m 644 "$SRC/palivane-api.service" /etc/systemd/system/palivane-api.service
systemctl daemon-reload
systemctl enable --now palivane-api
sleep 3
systemctl is-active --quiet palivane-api && echo "   palivane-api is running" || { echo "   service failed — journalctl -u palivane-api"; exit 1; }

# Admin helper so operators don't have to remember the env-sourcing dance.
cat > /usr/local/bin/palivane-admin <<WRAP
#!/usr/bin/env bash
set -euo pipefail
set -a; . $ENVFILE; set +a
# The systemd unit sets WorkingDirectory=$PREFIX/backend; this wrapper must do the same.
# The payload is a source tree, not an installed distribution, so \`python -m app.users\`
# from anywhere else dies with "No module named 'app'" — which is what every operator hit
# on the very next command the README tells them to run after installing.
cd $PREFIX/backend
exec sudo -u $SVCUSER env DATABASE_URL="\$DATABASE_URL" PALIVANE_SECRET_KEY="\$PALIVANE_SECRET_KEY" \\
  PYTHONPATH=$PREFIX/backend \\
  $PREFIX/backend/.venv/bin/python -m app.users "\$@"
WRAP
chmod +x /usr/local/bin/palivane-admin

cat <<EOF

Installed. The API + console are served on the port in palivane-api.service (default 8088);
put it behind your TLS reverse proxy (or the Cloudflare Worker) for real use.

Create the first org + admin:
  sudo palivane-admin create-tenant --slug acme --name "Acme"
  sudo palivane-admin create-user   --tenant acme --email admin@acme.local --role admin

Manage: systemctl {status,restart} palivane-api  ·  logs: journalctl -u palivane-api -f

Security defaults (in $ENVFILE):
  - This is a single-org install: PALIVANE_ALLOW_SIGNUP=false, so only users an admin
    adds can sign in. With signup on, anyone who reaches the console can create an org
    on this database and become its admin, and a weak PALIVANE_SECRET_KEY refuses to boot.
  - The default database is SQLite, which has NO row-level security: tenant isolation
    rests on application filters alone. Use Postgres (DATABASE_URL) for production and
    for anything that will hold more than one org.
  - GATEWAY_ENFORCE and CLIENT_ENFORCE both start false (monitor). Confirmed secret/PII
    leaks still block; set both to true together when you are ready to enforce.
EOF
# An env file kept from an earlier install predates these defaults; say what it is missing
# rather than editing an operator's file behind their back.
if ! grep -q '^PALIVANE_ALLOW_SIGNUP=' "$ENVFILE"; then
  echo
  echo "NOTE: $ENVFILE does not set PALIVANE_ALLOW_SIGNUP, so public org signup is ON."
  echo "      For a single-org install add PALIVANE_ALLOW_SIGNUP=false and restart palivane-api."
fi
grep -q '^CLIENT_ENFORCE=' "$ENVFILE" || \
  echo "NOTE: $ENVFILE does not set CLIENT_ENFORCE; hooks default to monitor. Keep it in step with GATEWAY_ENFORCE."
