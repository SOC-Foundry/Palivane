"""The developer meter: people each protection plane covered, per calendar month."""
from __future__ import annotations

from datetime import datetime

import pytest

from app import developer_meter as dm

HOOK_UA = "palivane-hook/1.2.0 (claude-code/2.1.4)"
PROXY_UA = "palivane-proxy/1.4.6"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/130"


@pytest.mark.parametrize("plane,tool,client,kind", [
    ("ai-usage", "claude-code", "palivane-hook", "agent"),
    ("ai-usage", "", "palivane-cursor-hook", "agent"),
    ("ai-usage", "claude-code", "palivane-proxy", "agent"),     # the proxy saw a coding assistant
    ("mcp", "Bash", "palivane-hook", "agent"),
    ("ai-usage", "claude-desktop", "palivane-proxy", "desktop"),
    ("ai-usage", "", "", "browser"),
    ("inference-hooks", "claude.ai", "", "claude_enterprise"),
    ("ci", "acme/api", "palivane-ci-scan", "ci"),
    ("posture", "mcp-config", "palivane-posture", None),
    ("a2a", "planner", "", None),
], ids=lambda v: str(v))
def test_classify(plane, tool, client, kind):
    assert dm.classify(plane, tool, client) == kind


def test_identity_is_the_same_person_on_every_plane_and_never_the_name():
    a = dm.identity_of(1, "agent", "Dev@Acme.com")
    assert a == dm.identity_of(1, "browser", "dev@acme.com ")
    assert a != dm.identity_of(2, "agent", "dev@acme.com")       # per tenant
    assert "acme" not in a and len(a) == 32
    assert dm.identity_of(1, "agent", "") == ""
    assert dm.identity_of(1, "ci", "someone", "acme/api") != dm.identity_of(1, "agent", "acme/api")


def _key(client, actor):
    return client.post("/api/apikeys", json={"label": f"k-{actor}", "actor": actor}).json()["token"]


def _send(raw_client, key, ua, user=""):
    r = raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": key, "User-Agent": ua},
                        json={"content": "summarise this meeting", "destination": "claude.ai",
                              "tool": "claude-code" if "hook" in ua else "", "user": user})
    assert r.status_code == 200, r.text


def _this_month(client):
    months = client.get("/api/fleet/developers", params={"months": 2}).json()["months"]
    assert months[0]["month"] == dm.month_of(datetime.utcnow())
    return months[0]


def test_capture_calls_are_metered_once_per_person_and_plane(client, raw_client):
    dm._SEEN.clear()
    k1, k2 = _key(client, "one@acme.com"), _key(client, "two@acme.com")
    for _ in range(3):
        _send(raw_client, k1, HOOK_UA)          # one agent-plane developer, many prompts
    _send(raw_client, k1, BROWSER_UA)           # ...who also uses the browser
    _send(raw_client, k2, BROWSER_UA)           # a browser-only person
    _send(raw_client, k2, PROXY_UA)             # ...also on a desktop app
    m = _this_month(client)
    assert m["agent"] == 1
    assert m["browser"] == 2 and m["desktop"] == 1
    assert m["browser_only"] == 1
    assert m["unattributed"] == 0


def test_backfill_is_idempotent_and_catches_unmetered_sensors(client, raw_client):
    dm._SEEN.clear()
    _send(raw_client, _key(client, "three@acme.com"), HOOK_UA)
    from app.database import get_db
    from app.main import app
    from app.models import DeveloperActivity
    gen = app.dependency_overrides.get(get_db, get_db)()
    db = next(gen)
    try:
        db.query(DeveloperActivity).delete()      # as if the capture-time write had failed
        db.commit()
        assert dm.backfill_from_heartbeats(db) >= 1
        assert dm.backfill_from_heartbeats(db) == 0
    finally:
        gen.close()
    assert _this_month(client)["agent"] >= 1


def test_the_endpoint_needs_an_admin(raw_client):
    assert raw_client.get("/api/fleet/developers").status_code in (401, 403)
