"""Regenerate every console screenshot the README + marketing pages embed.

Supersedes the one-off shot_help.mjs: one run rebuilds all of assets/*.png (login, connect,
dashboard, discovery, agents, policies, scanlog, help) against a LIVE local console, at the
same 1440@2x geometry as the originals. Console shots are full-page; the login card is
viewport-only.

    # local stack (frontend built; backend serving it), then:
    PALIVANE_URL=http://localhost:8088 backend/.venv/bin/python scripts/shots.py

Populate findings first (backend/.venv/bin/python -m app.seed, then scripts/demo_capture.py)
so the dashboards aren't empty. Copies of some shots ship in frontend/public/shots/ — those
are served through Cloudflare, which caches by path, so give them a NEW filename when they
change and bump the components that reference them (same rule as the videos).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

BASE = os.getenv("PALIVANE_URL", "http://localhost:8088").rstrip("/")
EMAIL = os.getenv("SEED_ADMIN_EMAIL", "admin@demo.local")
PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "changeme123")
OUT_DIR = os.getenv("SHOTS_OUT", os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "assets"))

# (file, sidebar tab, full-page, viewport-height). login is special-cased: logged-out,
# #signin, viewport. policies is NOT full-page on purpose: the page runs very tall
# (every check group + overrides), which squashes to an unreadable sliver in the landing
# gallery — a 1100px top-of-page framing shows the check toggles the caption talks about.
# Pass shot names as argv to regenerate a subset (e.g. `shots.py policies.png`).
SHOTS = [
    ("connect.png", "Connect", True, 900),
    ("dashboard.png", "Findings", True, 900),
    ("discovery.png", "Discovery", True, 900),
    ("agents.png", "Agents", True, 900),
    ("policies.png", "Policies", False, 1100),
    ("scanlog.png", "Scan log", True, 900),
    ("help.png", "Help", True, 900),
]


def main() -> int:
    from playwright.sync_api import sync_playwright

    only = set(sys.argv[1:])
    req = urllib.request.Request(
        BASE + "/api/auth/login", method="POST",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"content-type": "application/json"})
    token = json.loads(urllib.request.urlopen(req, timeout=30).read())["access_token"]

    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--disable-dev-shm-usage", "--no-sandbox"])

        # Logged-out login card (viewport, not full-page).
        if not only or "login.png" in only:
            ctx = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
            page = ctx.new_page()
            page.goto(BASE + "/#signin", wait_until="networkidle")
            page.wait_for_timeout(600)
            page.screenshot(path=os.path.join(OUT_DIR, "login.png"))
            print("  login.png")
            ctx.close()

        # Signed-in console pages (a fresh context per shot so viewport height can vary).
        for fname, tab, fullpage, height in SHOTS:
            if only and fname not in only:
                continue
            ctx = b.new_context(viewport={"width": 1440, "height": height},
                                device_scale_factor=2)
            page = ctx.new_page()
            page.add_init_script(f"localStorage.setItem('palivane_token', {json.dumps(token)})")
            page.goto(BASE, wait_until="networkidle")
            page.wait_for_timeout(1200)
            try:
                page.get_by_role("button", name=tab, exact=True).click()
                page.wait_for_timeout(900)
            except Exception as e:
                print(f"  {fname}: could not open {tab} ({str(e)[:60]})")
                ctx.close()
                continue
            page.screenshot(path=os.path.join(OUT_DIR, fname), full_page=fullpage)
            print(f"  {fname}")
            ctx.close()
        b.close()
    print(f"\nwrote shots to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
