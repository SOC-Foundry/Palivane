"""Opt-in integration test: the extension's real fetch-interceptor blocks sensitive
prompts before they leave the browser, with verdicts from a running backend.

Loads the real `extension/injected.js` into a Chromium page that mimics how
ChatGPT/Claude submit a prompt; the 'background' relay calls the live Palivane
ai-usage endpoint. Skipped unless pointed at a running backend:

    EXTENSION_INGEST_TOKEN=ext-demo-token-123 INGEST_TENANT=demo  # on the backend
    PALIVANE_EXT_URL=http://localhost:8090 PALIVANE_EXT_TOKEN=ext-demo-token-123 \
    pytest backend/tests/test_extension_intercept.py
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

import pytest

URL = os.getenv("PALIVANE_EXT_URL")
TOKEN = os.getenv("PALIVANE_EXT_TOKEN", "")
INJECTED = Path(__file__).resolve().parents[2] / "extension" / "injected.js"

pytestmark = pytest.mark.skipif(not URL, reason="set PALIVANE_EXT_URL to run the extension interceptor test")

SETUP = """
() => {
  window.__events = [];
  window.fetch = async () => new Response('{"ok":true}', {status: 200});
  window.addEventListener('message', async (e) => {
    const d = e.data;
    if (!d || !d.__warden) return;
    if (d.kind === 'scan') {
      const verdict = await window.wardenScan(d.content, d.destination);
      window.postMessage({__warden:true, kind:'verdict', id:d.id, verdict}, '*');
    } else if (d.kind === 'blocked' || d.kind === 'warn') {
      window.__events.push({kind:d.kind, verdict:d.verdict});
    }
  });
}
"""

SUBMIT = """
async (prompt) => {
  const res = await window.fetch('/backend-api/conversation', {
    method: 'POST',
    body: JSON.stringify({messages: [{author: {role: 'user'}, content: {parts: [prompt]}}]}),
  });
  await new Promise(r => setTimeout(r, 50));
  return {status: res.status, events: window.__events};
}
"""


def _scan(content, destination):
    req = urllib.request.Request(
        URL.rstrip("/") + "/api/ingest/ai-usage", method="POST",
        data=json.dumps({"content": content, "destination": destination, "user": "tester"}).encode(),
        headers={"content-type": "application/json", "X-Palivane-Token": TOKEN},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def test_interceptor_blocks_sensitive_prompt():
    sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed")
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page()
        page.expose_function("wardenScan", _scan)
        page.goto("about:blank")
        page.evaluate(SETUP)
        page.add_script_tag(content=INJECTED.read_text())

        benign = page.evaluate(SUBMIT, "Brainstorm five taglines for our launch.")
        assert benign["status"] == 200 and benign["events"] == []

        leak = page.evaluate(SUBMIT, "John Doe SSN 123-45-6789, AWS key AKIAABCDEFGHIJKLMNOP")
        assert leak["status"] == 451                       # intercepted, not sent
        assert any(e["kind"] == "blocked" for e in leak["events"])
        browser.close()
