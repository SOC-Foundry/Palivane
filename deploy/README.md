# Deploying Palivane

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
sudoedit /etc/warden/warden.env     # set DATABASE_URL, PALIVANE_SECRET_KEY, gateway/keys
```

`DATABASE_URL` should point at `/var/lib/warden` (the only path the hardened units
may write to), e.g. `sqlite:////var/lib/warden/warden.db`. Set a strong
`PALIVANE_SECRET_KEY` (`openssl rand -hex 32`) — auth tokens are signed with it.

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

## Scheduled S3 scanning

`palivane-s3-scan` sweeps an S3 bucket's objects for secrets/PII at rest and flags public
exposure — but nothing triggers it until you schedule it. The instanced units
[`palivane-s3-scan@.service`](./palivane-s3-scan@.service) + [`palivane-s3-scan@.timer`](./palivane-s3-scan@.timer)
run **one scan per bucket, daily** (the `%i` instance is the bucket name).

```bash
# On a box that can reach Palivane and the buckets (a "security" instance is ideal):
curl -fsSL "$PALIVANE_URL/cli/palivane-s3-scan" -o /opt/warden/bin/palivane-s3-scan
sudo chmod +x /opt/warden/bin/palivane-s3-scan
sudo -u warden /opt/warden/backend/.venv/bin/pip install boto3   # the scanner needs boto3

# PALIVANE_URL + PALIVANE_TOKEN go in /etc/warden/warden.env; AWS creds are best supplied by the
# box's instance role (else add AWS_* / AWS_REGION to the same env file).
sudo cp /opt/warden/deploy/palivane-s3-scan@.service /opt/warden/deploy/palivane-s3-scan@.timer \
        /etc/systemd/system/
sudo systemctl daemon-reload

# Enable a daily scan per bucket (repeat per bucket; systemd-escape names with '/' or '.'):
sudo systemctl enable --now palivane-s3-scan@my-data-bucket.timer
sudo systemctl enable --now palivane-s3-scan@my-exports-bucket.timer

systemctl list-timers 'palivane-s3-scan@*'                 # confirm the schedule
journalctl -u 'palivane-s3-scan@my-data-bucket.service'    # see a run's output
```

Prefer cron? The equivalent one-liner (e.g. in `/etc/cron.d/palivane-s3-scan`):

```cron
17 3 * * *  warden  PALIVANE_URL=https://palivane.corp.example.com PALIVANE_TOKEN=ak_… /opt/warden/bin/palivane-s3-scan my-data-bucket --record --fail-closed
```

For the org-wide **GitHub** sweep, use the scheduled Action template
[`git/warden-org-scan.yml`](../git/warden-org-scan.yml) instead — CI is the natural home for
a repo scan.

The connectors exchange the refresh token for a short-lived access token on each run,
so no interactive login is needed once configured.
