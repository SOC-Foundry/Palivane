"""Collect the REAL verdicts the hero video renders.

Nothing in the video is mocked detection: every risk score, category list, and remediation
line below comes back from a live Warden backend over its real endpoints. This script
drives that backend and writes one JSON blob that scripts/demo_video.py renders.

    ./run-local.sh                 # in another shell
    backend/.venv/bin/python scripts/demo_capture.py

Env: WARDEN_URL (default http://localhost:8088), plus the run-local seed credentials.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.getenv("WARDEN_URL", "http://localhost:8088").rstrip("/")
EMAIL = os.getenv("SEED_ADMIN_EMAIL", "admin@demo.local")
PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "changeme123")
OUT = os.getenv("DEMO_DATA", "/tmp/warden-demo/verdicts.json")

# --- the payloads each scene sends. Realistic, and every one is genuinely detectable. ---
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"          # AWS's own documented example key id
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

BROWSER_PROMPT = (
    "Here's the failing export, can you tell me why the totals are off?\n\n"
    "customer,email,ssn,card\n"
    "Dana Whitfield,dana.whitfield@northgate-health.com,412-88-7390,4539 8821 4471 0033\n"
    "Marcus Ruiz,m.ruiz@northgate-health.com,501-22-9948,5425 2334 3010 9903\n\n"
    "# the job auths with\n"
    f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
    f"AWS_SECRET_ACCESS_KEY={SECRET}\n"
)

CODE_PROMPT = (
    "Fix the failing integration test in billing/reconcile.py. Here is the config it loads:\n\n"
    f"STRIPE_SECRET_KEY=sk_live_51Nc8kLJx2eR4tQmZvB7yHgW3\n"
    f"DATABASE_URL=postgres://svc_billing:Pr0dDb!2024@prod-db.internal:5432/billing\n"
    f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
)

S3_OBJECTS = [
    {"key": "exports/2026-07/customers.csv",
     "content": "name,email,ssn\nDana Whitfield,dana@northgate-health.com,412-88-7390\n"},
    {"key": "backups/env.production",
     "content": f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY={SECRET}\n"
                "DATABASE_URL=postgres://svc:Pr0dDb!2024@prod-db.internal:5432/billing\n"},
    {"key": "public/readme.md", "content": "# Data exports\nRotated weekly.\n"},
]

CI_WORKFLOW = """name: agent triage
on: pull_request_target
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v44
      - name: let the agent fix it
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: claude -p "triage this PR and push a fix" --dangerously-skip-permissions
"""


def _post(path: str, body: dict, headers: dict | None = None) -> dict:
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main() -> int:
    # This script POSTs recorded findings, so it must never be pointed at a real tenant by
    # a stray WARDEN_URL in someone's shell (mine was set to production). Local only,
    # unless the caller opts out on purpose.
    host = urllib.parse.urlparse(BASE).hostname or ""
    if host not in ("localhost", "127.0.0.1", "::1") and not os.getenv("DEMO_ALLOW_REMOTE"):
        print(f"refusing to write demo findings to {BASE} — set WARDEN_URL to a local "
              "instance (or DEMO_ALLOW_REMOTE=1 if you really mean it).", file=sys.stderr)
        return 2
    try:
        session = _post("/api/auth/login", {"email": EMAIL, "password": PASSWORD})["access_token"]
    except (urllib.error.URLError, OSError) as e:
        print(f"cannot reach {BASE} ({e}) — is ./run-local.sh running?", file=sys.stderr)
        return 1
    auth = {"Authorization": f"Bearer {session}"}
    key = _post("/api/apikeys", {"label": "demo-video"}, auth)["token"]
    tok = {"X-Warden-Token": key}

    out: dict = {}

    # 1-3. Browser planes (claude.ai / ChatGPT / Gemini) — the extension's scan call.
    for name, dest in (("claude", "https://claude.ai/"),
                       ("chatgpt", "https://chatgpt.com/"),
                       ("gemini", "https://gemini.google.com/")):
        out[name] = _post("/api/ingest/ai-usage", {
            "content": BROWSER_PROMPT, "destination": dest, "user": "dana@northgate.io",
            "tool": name}, tok)

    # 4-6. Coding agents. Claude Code and Cursor go through the LLM gateway (a real 400);
    #      the Codex CLI hook scores the prompt locally and blocks it before it is sent.
    for name in ("claudecode", "cursor"):
        try:
            _post("/v1/messages", {
                "model": "claude-opus-4-8", "max_tokens": 256,
                "messages": [{"role": "user", "content": CODE_PROMPT}]},
                {**tok, "x-api-key": key})
            out[name] = {"blocked": False}
        except urllib.error.HTTPError as e:
            out[name] = {"blocked": True, "status": e.code,
                         "body": json.loads(e.read().decode())}
    out["codex"] = _post("/api/ingest/ai-usage", {
        "content": CODE_PROMPT, "destination": "", "user": "dana@northgate.io",
        "tool": "codex"}, tok)

    # 7. AWS — a public bucket holding an export and a production .env.
    out["aws"] = _post("/api/scan/s3", {
        "bucket": "northgate-data-exports", "region": "us-east-1", "public": True,
        "objects": S3_OBJECTS, "record": True}, tok)

    # 8. GitHub — an Actions workflow that runs an agent with production credentials.
    out["github"] = _post("/api/scan/ci", {
        "repo": "northgate/billing", "ref": "main", "record": True,
        "workflows": [{"path": ".github/workflows/agent-triage.yml", "content": CI_WORKFLOW}]}, tok)

    out["_inputs"] = {"browser_prompt": BROWSER_PROMPT, "code_prompt": CODE_PROMPT,
                      "ci_workflow": CI_WORKFLOW, "s3_objects": S3_OBJECTS}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)

    for k in ("claude", "chatgpt", "gemini", "codex"):
        v = out[k]
        print(f"{k:11s} action={v.get('action'):6s} risk={v.get('risk_score')} "
              f"sev={v.get('severity')}")
    for k in ("claudecode", "cursor"):
        v = out[k]
        print(f"{k:11s} blocked={v.get('blocked')} "
              f"{(v.get('body', {}).get('error', {}).get('message', '') or '')[:70]}")
    print(f"aws         action={out['aws'].get('action')} "
          f"flagged={len(out['aws'].get('objects', []))} of {out['aws'].get('scanned')}")
    print(f"github      action={out['github'].get('action')} "
          f"flagged={len(out['github'].get('workflows', []))}")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
