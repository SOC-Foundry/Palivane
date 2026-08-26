"""Public read-only demo: token minting, read-only enforcement, throttling."""

from __future__ import annotations

import app.demo as demo
from app.models import Tenant


def _enable(monkeypatch, db_factory, slug="acme"):
    monkeypatch.setattr(demo.settings, "demo_org", slug)


def test_dark_by_default(raw_client):
    assert raw_client.post("/api/auth/demo").status_code == 404
    assert raw_client.get("/api/health").json()["demo"] is False


def test_unseeded_org_503(raw_client, monkeypatch):
    monkeypatch.setattr(demo.settings, "demo_org", "ghost")
    assert raw_client.post("/api/auth/demo").status_code == 503


def test_demo_session_browses_but_cannot_mutate(client, raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    r = raw_client.post("/api/auth/demo")
    assert r.status_code == 200 and r.json()["demo"] is True
    tok = {"Authorization": f"Bearer {r.json()['access_token']}"}
    # reads work
    assert raw_client.get("/api/findings", headers=tok).status_code == 200
    assert raw_client.get("/api/auth/me", headers=tok).status_code == 200
    # mutation is refused with the signup pointer
    upd = raw_client.post("/api/auth/logout-all", headers=tok)
    assert upd.status_code == 403 and "read-only" in upd.json()["detail"]
    # the viewer is an analyst — no admin surface even for reads
    assert raw_client.get("/api/users", headers=tok).status_code == 403


def test_demo_viewer_is_reused_not_duplicated(client, raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    assert raw_client.post("/api/auth/demo").status_code == 200
    assert raw_client.post("/api/auth/demo").status_code == 200
    from app.models import User
    db = db_factory()
    n = db.query(User).filter(User.email == demo.DEMO_VIEWER).count()
    db.close()
    assert n == 1


def test_demo_throttled_per_ip(client, raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    monkeypatch.setattr(demo.settings, "login_ip_max_fails", 3)
    codes = [raw_client.post("/api/auth/demo").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]
