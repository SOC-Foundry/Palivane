#!/usr/bin/env bash
# Palivane native installer — run Palivane directly on a server, NO Docker.
#
# Run as root on the TARGET server from an extracted release tarball (built by
# build-release.sh). The target needs only Python 3.12+ (and Postgres for production; the
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
command -v python3 >/dev/null || { echo "python3 3.12+ is required" >&2; exit 1; }
PYV="$(python3 -c 'import sys;print("%d%02d"%sys.version_info[:2])')"
[ "$PYV" -ge 312 ] || { echo "Python 3.12+ required (found $(python3 -V))" >&2; exit 1; }
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
python3 -m venv "$PREFIX/backend/.venv"
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
set -a; . $ENVFILE; set +a
exec sudo -u $SVCUSER env DATABASE_URL="\$DATABASE_URL" PALIVANE_SECRET_KEY="\$PALIVANE_SECRET_KEY" \\
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
EOF
