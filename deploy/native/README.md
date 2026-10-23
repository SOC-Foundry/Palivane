# Palivane — native install (no Docker)

Run Palivane directly on a Linux server as a systemd service — no Docker, no container
runtime. Same app as the SaaS/compose image; just installed on the host. Serves the SPA +
API + the `/install.sh` & `/cli` endpoints single-origin on one port.

## Two steps

**1. Build the release tarball** (on any box with Python + Node — your laptop or CI):
```bash
./deploy/native/build-release.sh
# -> dist/palivane-native-<tag>.tar.gz  (frontend prebuilt; no Node needed on the server)
```

**2. Install on the target server** (needs only Python 3.12+; Postgres for production):
```bash
tar xzf palivane-native-<tag>.tar.gz
sudo ./palivane/install.sh
sudo palivane-admin create-tenant --slug acme --name "Acme"
sudo palivane-admin create-user   --tenant acme --email admin@acme.local --role admin
```
The installer creates a `palivane` system user, a venv at `/opt/palivane`, `/etc/palivane/palivane.env`
(with a generated `PALIVANE_SECRET_KEY` and a SQLite default), runs migrations, and starts the
`palivane-api` systemd service.

## Production notes
- **Use Postgres**, not the default SQLite: edit `DATABASE_URL` in `/etc/palivane/palivane.env`
  (e.g. `postgresql+psycopg2://palivane:PASS@localhost/palivane`) and `systemctl restart palivane-api`.
  The app enforces a strong `PALIVANE_SECRET_KEY` on non-SQLite (JWTs would be forgeable otherwise).
  SQLite has **no row-level security**: tenant isolation rests on the application's filters
  alone, so anything holding more than one org belongs on Postgres.
- **Signup is off.** This is a single-org install, so the generated env file sets
  `PALIVANE_ALLOW_SIGNUP=false` and only users an admin adds can sign in. With signup on, anyone
  who reaches the console can create an org on the same database and become its admin; on
  SQLite that combination with a weak `PALIVANE_SECRET_KEY` refuses to boot. An env file kept
  from an earlier install is not edited; the installer prints a note if it lacks the setting.
- **Enforcement** starts in monitor: `GATEWAY_ENFORCE=false` (LLM gateway) and
  `CLIENT_ENFORCE=false` (CLI hooks and desktop proxy on devices with no local flag). Set both to
  `true` together; confirmed secret/PII leaks block in either mode.
- **TLS**: the service listens on `:8088` (see `palivane-api.service`). Front it with nginx/Caddy
  for HTTPS, or the same Cloudflare Worker pattern as the SaaS.
- **Config** lives in `/etc/palivane/palivane.env` (mode 600) — judge keys, gateway upstreams,
  SMTP, posture toggles (`PALIVANE_ENCRYPT_FINDINGS`, `PALIVANE_STORE_CONTENT`, `GATEWAY_ENFORCE`).
- **Upgrades**: build a new tarball, re-run `install.sh` (it preserves an existing env file and
  re-runs migrations), `systemctl restart palivane-api`.

## Manage
```
systemctl status palivane-api      # health
journalctl -u palivane-api -f      # logs
palivane-admin ...                 # tenant/user admin (list-tenants, set-quota, suspend, …)
```
