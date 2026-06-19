# Deploying Warden

A systemd unit for running the API as a service. Adjust paths/user to taste; this
assumes the layout below. (The browser extension and egress proxy are deployed
separately — see [`extension/`](../extension/) and [`proxy/`](../proxy/).)

```
/opt/warden/            # checkout (backend/ + frontend/)
/opt/warden/backend/.venv  # virtualenv with requirements installed
/etc/warden/warden.env   # secrets + config (chmod 600)
/var/lib/warden/           # writable state (sqlite db); owned by the service user
```

## 1. System user and directories

```bash
sudo useradd --system --home /opt/warden --shell /usr/sbin/nologin warden
sudo mkdir -p /opt/warden /etc/warden /var/lib/warden
sudo chown -R warden:warden /opt/warden /var/lib/warden
```

## 2. Install the app

```bash
sudo -u warden git clone <repo> /opt/warden
cd /opt/warden/backend
sudo -u warden python3 -m venv .venv
sudo -u warden .venv/bin/pip install -r requirements.txt
```

## 3. Configure

```bash
sudo cp /opt/warden/deploy/warden.env.example /etc/warden/warden.env
sudo chown warden:warden /etc/warden/warden.env
sudo chmod 600 /etc/warden/warden.env
sudoedit /etc/warden/warden.env     # set DATABASE_URL, WARDEN_SECRET_KEY, gateway/keys
```

`DATABASE_URL` should point at `/var/lib/warden` (the only path the hardened units
may write to), e.g. `sqlite:////var/lib/warden/warden.db`. Set a strong
`WARDEN_SECRET_KEY` (`openssl rand -hex 32`) — auth tokens are signed with it.

## 3b. Create the first tenant and admin

```bash
cd /opt/warden/backend
sudo -u warden .venv/bin/python -m app.users create-tenant --slug acme --name "Acme Corp"
sudo -u warden .venv/bin/python -m app.users create-user --tenant acme --email soc@acme.com --role admin
```

Set `INGEST_TENANT` in the env file to that tenant's slug so the extension/proxy
attribute findings to it.

## 4. Install units

```bash
sudo cp /opt/warden/deploy/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## 5. Start

```bash
sudo systemctl enable --now warden-api.service
```

## Verify

```bash
systemctl status warden-api.service
journalctl -u warden-api.service -f
curl -s localhost:8088/api/health
```

For most deployments you'd run the full stack with `docker compose up` instead (Postgres
+ API + web); these units are for a bare-metal/systemd install of the API.

The connectors exchange the refresh token for a short-lived access token on each run,
so no interactive login is needed once configured.
