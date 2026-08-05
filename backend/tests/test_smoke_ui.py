"""Opt-in end-to-end UI smoke test.

The unit suite can't catch render-time bugs (a hooks-order crash blanks the page
while every API test still passes). This drives a real browser against a running
stack and asserts the dashboard renders after login.

It is skipped unless you point it at a running deployment and have Playwright +
Chromium installed:

    pip install playwright && playwright install chromium
    docker compose up --build           # or run the dev servers
    PALIVANE_SMOKE_URL=http://localhost:8090 \
    PALIVANE_SMOKE_EMAIL=admin@demo.local \
    PALIVANE_SMOKE_PASSWORD=changeme123 \
    pytest backend/tests/test_smoke_ui.py
"""

from __future__ import annotations

import os

import pytest

URL = os.getenv("PALIVANE_SMOKE_URL")
EMAIL = os.getenv("PALIVANE_SMOKE_EMAIL", "admin@demo.local")
PASSWORD = os.getenv("PALIVANE_SMOKE_PASSWORD", "changeme123")

pytestmark = pytest.mark.skipif(not URL, reason="set PALIVANE_SMOKE_URL to run the UI smoke test")


def test_login_and_dashboard_render():
    sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed")

    errors = []
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page()
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        page.goto(URL, wait_until="networkidle")
        page.fill("input[type=email]", EMAIL)
        page.fill("input[type=password]", PASSWORD)
        page.click('button:has-text("Sign in")')

        # Dashboard chrome must appear (regression guard for the hooks-order crash).
        page.wait_for_selector("text=Analyze content", timeout=15000)
        page.wait_for_selector("text=Total analyzed", timeout=15000)
        browser.close()

    assert not errors, f"console errors on render: {errors[:3]}"
