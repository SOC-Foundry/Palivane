---
name: run-local
description: Launch the Palivane app locally (FastAPI backend serving the built SPA from a single origin) against a fresh seeded sqlite DB, then drive the console to verify it works. Use when you need to run Palivane locally, smoke-test the SPA end to end, or walk every console tab after a merge.
---

# Run Palivane locally + walk the console

The whole app ships as one Cloud Run image: the FastAPI backend serves the built
React SPA. Locally you reproduce that single-origin setup — no separate Vite dev
server needed for a smoke test, and single-origin means the console's relative
`/api` calls just work without any `VITE_PALIVANE_APP_ORIGIN` wiring.

Verified working on this repo (Aug 2026). If a step fails on mechanics unrelated
to your task, the recipe has drifted — refresh this skill.

## One-time setup

Backend venv (CI pins Python 3.12; 3.14 also works locally). `libxmlsec1` is
needed for the SAML deps to install:

```bash
sudo apt-get install -y --no-install-recommends libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Build the SPA (writes `frontend/dist`, which the backend serves):

```bash
cd frontend && npm ci && npm run build
```

## Launch with seeded data

Use an **absolute** sqlite path — a relative `sqlite:///./x.db` resolves against
the process cwd and bites you. sqlite auto-creates the schema on boot (Postgres
would need `alembic upgrade head`; sqlite does not). `python -m app.seed` is
idempotent — it clears findings first — and prints the admin login.

```bash
cd backend
DB=/tmp/palivane-local.db           # anywhere writable and absolute
export DATABASE_URL="sqlite:///$DB"
export PALIVANE_SECRET_KEY="dev-local-fixedsecret-abc123456789"   # >=16 chars; sqlite=dev, weak key allowed
export PALIVANE_DEMO_ORG="demo"                                    # enables the /#demo read-only login
export PALIVANE_STATIC_DIR="$PWD/../frontend/dist"                # makes the backend serve the SPA
rm -f "$DB"
.venv/bin/python -m app.seed        # -> "Seeded 19 findings ... admin@demo.local / changeme123"
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8099 --log-level warning
```

Run uvicorn as a background task (not `&`), then poll readiness — do not
foreground-`sleep`:

```bash
curl -s http://127.0.0.1:8099/api/health     # {"status":"ok",...,"demo":true}
```

The seeded admin is `admin@demo.local` / `changeme123`, org slug `demo`. The 19
findings are attributed to demo users (alice@demo.local, …), so the **Your
findings** tab is legitimately empty for admin — that is correct, not a bug.

## Drive it — walk every console tab

Sign in and click through all 18 nav tabs, capturing per-tab console errors,
failed `/api` calls, headings, and screenshots. The driver is next to this file:

```bash
node .claude/skills/run-local/walk.mjs        # BASE defaults to http://127.0.0.1:8099
```

The driver needs `playwright-core` and system Chrome
(`/usr/bin/google-chrome-stable`). It auto-discovers `playwright-core` from the
cwd, the repo's `frontend/`, or the machine's VS Code bundle; if none has it,
`(cd frontend && npm i -D playwright-core)` or set `PW_CORE=/path/to/node_modules/x.js`.
It writes `walk-results.json` + `shots/tab-*.png` in the cwd and prints a
`SUMMARY` with an issue count. **Look at a screenshot or two** — a green
"0 issues" only means no thrown errors, not that the page rendered.

Expected: 18 tabs, 0 console errors, 0 failed API calls. The **Connect** tab
shows an informational "No model provider key set" banner (styled `.error` but
it's just a notice — expected locally with no Anthropic key); the walk script
whitelists it. **Audit** shows an empty state until an admin action is recorded.

## Teardown

Stop the uvicorn background task (TaskStop, not `pkill` in a compound command —
that has killed the shell here). The sqlite DB is a throwaway temp file.

## Gotchas seen
- Relative `sqlite:///./…` URLs resolve against cwd — always use an absolute path.
- Without `PALIVANE_STATIC_DIR` the backend serves the API only; `/` 404s. Point it at `frontend/dist` (build first).
- A `PALIVANE_SECRET_KEY` under 16 chars, or a known-weak value, boots on sqlite with a warning but **refuses to boot on Postgres**.
