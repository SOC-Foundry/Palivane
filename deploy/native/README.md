# Palivane — native install (no Docker)

Run Palivane directly on a Linux server as a systemd service — no Docker, no container
runtime. Same app as the SaaS/compose image; just installed on the host. Serves the SPA +
API + the `/install.sh` & `/cli` endpoints single-origin on one port.

## Two steps

**1. Build the release tarball** (on any box with Python + Node — your laptop or CI):
```bash
./deploy/native/build-release.sh
# -> dist/warden-native-<tag>.tar.gz  (frontend prebuilt; no Node needed on the server)
```

**2. Install on the target server** (needs only Python 3.12+; Postgres for production):
```bash
tar xzf warden-native-<tag>.tar.gz
sudo ./warden/install.sh
sudo warden-admin create-tenant --slug acme --name "Acme"
sudo warden-admin create-user   --tenant acme --email admin@acme.local --role admin
```
The installer creates a `warden` system user, a venv at `/opt/warden`, `/etc/warden/warden.env`
(with a generated `PALIVANE_SECRET_KEY` and a SQLite default), runs migrations, and starts the
`warden-api` systemd service.

## Production notes
- **Use Postgres**, not the default SQLite: edit `DATABASE_URL` in `/etc/warden/warden.env`
  (e.g. `postgresql+psycopg2://warden:PASS@localhost/warden`) and `systemctl restart warden-api`.
  The app enforces a strong `PALIVANE_SECRET_KEY` on non-SQLite (JWTs would be forgeable otherwise).
- **TLS**: the service listens on `:8088` (see `warden-api.service`). Front it with nginx/Caddy
  for HTTPS, or the same Cloudflare Worker pattern as the SaaS.
- **Config** lives in `/etc/warden/warden.env` (mode 600) — judge keys, gateway upstreams,
  SMTP, posture toggles (`PALIVANE_ENCRYPT_FINDINGS`, `PALIVANE_STORE_CONTENT`, `GATEWAY_ENFORCE`).
- **Upgrades**: build a new tarball, re-run `install.sh` (it preserves an existing env file and
  re-runs migrations), `systemctl restart warden-api`.

## Manage
```
systemctl status warden-api      # health
journalctl -u warden-api -f      # logs
warden-admin ...                 # tenant/user admin (list-tenants, set-quota, suspend, …)
```
