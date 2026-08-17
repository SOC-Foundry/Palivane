# Running Warden locally (no Docker)

Run the **full** Warden app — SPA + API, single-origin — natively on your machine.
No Docker, no container runtime, no Postgres. It uses a Python virtualenv, a prebuilt
copy of the web UI, and a local **SQLite** database file.

Everything below has been set up already; the [Daily use](#daily-use) section is all you
need day-to-day. The [One-time setup](#one-time-setup) section is here so it's reproducible
on a fresh clone or another machine.

---

## Prerequisites

- **Python 3.12** — the backend deps are pinned to 3.12 (the version the SaaS image uses).
  We use [`uv`](https://github.com/astral-sh/uv) to fetch a standalone 3.12 so your system
  Python is left alone. (`uv` also just works as a fast `pip`.)
- **Node 20+** — only to build the web UI once. Not needed to *run* Warden after that.

Check:
```bash
uv --version      # any recent version
node -v           # v20 or newer
```

---

## Daily use

From the repo root (`~/Aithreat`):

```bash
./run-local.sh
```

Then open **http://localhost:8088** and sign in with the seeded demo admin:

| | |
|---|---|
| **URL** | http://localhost:8088 |
| **Email** | `admin@demo.local` |
| **Password** | `changeme123` |

Stop it with **Ctrl-C**.

Handy variants:
```bash
./run-local.sh --seed        # wipe & re-create the demo findings
PORT=9000 ./run-local.sh     # run on a different port
```

The first run generates `.env.local` (holding a random `WARDEN_SECRET_KEY` and the SQLite
path), applies DB migrations, and seeds a demo org. Subsequent runs just migrate and start.

---

## What it starts

- **One process**: `uvicorn` serving both the API and the React SPA on `:8088`
  (same single-origin image the SaaS runs — just from source instead of a container).
- **Database**: `warden-local.db` (SQLite) in the repo root.
- **API docs**: http://localhost:8088/api/docs (FastAPI interactive docs).
- **Health**: http://localhost:8088/api/health.

Everything the console needs runs **offline** — the LLM "judge" is optional and off unless
you add a key (see [Optional](#optional-extras)).

---

## One-time setup

Already done in this repo, but to reproduce from a fresh clone:

```bash
cd ~/Aithreat

# 1. Python 3.12 venv + backend deps (uv downloads 3.12 if you don't have it)
uv venv --python 3.12 .venv-local
uv pip install --python .venv-local/bin/python -r backend/requirements.txt

# 2. Build the web UI once (produces frontend/dist/, served single-origin)
cd frontend && npm ci && npm run build && cd ..

# 3. Start
./run-local.sh
```

`.venv-local/`, `.env.local`, `warden-local.db`, and `.seeded` are all git-ignored.

---

## Managing data

```bash
# Create another org + admin (instead of / in addition to the demo one):
set -a; . .env.local; set +a
cd backend
../.venv-local/bin/python -m app.users create-tenant --slug acme --name "Acme"
../.venv-local/bin/python -m app.users create-user   --tenant acme --email you@acme.local --role admin
cd ..

# Start completely fresh (deletes all local data):
rm -f warden-local.db && ./run-local.sh
```

### Clearing the Warden key / local config

There are two independent places a "Warden key" lives:

```fish
# 1. Proxy/shell env vars left over from testing the egress proxy (fish syntax):
set -e WARDEN_TOKEN WARDEN_URL WARDEN_PROXY_ENFORCE WARDEN_PROXY_USER

# 2. The app's generated secret + local config. Deleting .env.local regenerates a fresh
#    WARDEN_SECRET_KEY on the next run (this invalidates existing logins — just sign in again):
rm -f .env.local && ./run-local.sh
```

The **browser extension's** ingest token is *not* on disk — it's in the browser's
`chrome.storage`. Clear it from the extension's **Options** page: blank the *Ingest token*
field and Save. With no token the extension goes dormant (`action: allow`, reason
`unconfigured`) and stops calling the backend.

---

## Optional extras

Add these to `.env.local` (then restart) to turn on optional features:

```bash
# LLM judge — reads content like an analyst for cases the rules miss (costs API calls):
ANTHROPIC_API_KEY=sk-ant-...
# or OPENAI_API_KEY=... / GEMINI_API_KEY=...

# Keep the prompt text on findings (default: metadata-only, no prose stored):
WARDEN_STORE_CONTENT=true
WARDEN_ENCRYPT_FINDINGS=true   # encrypt that stored content at rest
```

---

## Uninstall / clean up

There's nothing installed system-wide. To remove all local traces:

```bash
rm -rf .venv-local frontend/dist warden-local.db .env.local .seeded
```

---

## Troubleshooting

- **`venv missing`** — run the [one-time setup](#one-time-setup).
- **`SPA not built`** — `cd frontend && npm ci && npm run build`.
- **Port 8088 already in use** — `PORT=9000 ./run-local.sh` (note: host `:8080` is used by
  another app on this machine, and `:8090` by the old Docker Warden stack, so 8088 is the
  default here).
- **`405 Method Not Allowed` on every prompt in the AI tool (even with no secret/PII)** —
  traffic is being pointed at the **app** port `:8088` as if it were a forward proxy. It
  isn't: `:8088` is a normal web server, so a proxied prompt POST lands on the SPA's
  GET-only catch-all route and comes back `405` — for *every* request, regardless of
  content. There are two separate capture planes; don't mix them:
    - **Browser extension** — set its *backend URL* (extension Options) to
      `http://localhost:8088` and set **no** OS/browser network proxy. The extension calls
      the ingest API directly and never proxies your prompt traffic.
    - **Egress proxy** — a *separate* mitmproxy process on **`:8081`**. Point the
      browser/system proxy at `:8081` (not `:8088`), and give the addon
      `WARDEN_URL=http://localhost:8088` so it reports back to the app. See `proxy/README.md`.

  Rule of thumb: **`:8088` = the Warden app; `:8081` = the proxy the browser talks to.** They
  are not interchangeable.
- **Login fails after editing `.env.local`** — changing `WARDEN_SECRET_KEY` invalidates
  existing sessions; just sign in again.
- **Want Postgres instead of SQLite** — set `DATABASE_URL=postgresql+psycopg2://user:pass@localhost/warden`
  in `.env.local` and restart (a strong `WARDEN_SECRET_KEY` is enforced on non-SQLite).

---

## How this differs from the other run options

| Option | Command | When |
|---|---|---|
| **Local run (this doc)** | `./run-local.sh` | Run/test on your own machine, no root, deletes cleanly. |
| **Docker compose** | `docker compose up --build` | Container-based local/self-host stack (Postgres + the canonical image). |
| **Native systemd** | `deploy/native/install.sh` | Run as a server service (starts on boot, needs root). |
