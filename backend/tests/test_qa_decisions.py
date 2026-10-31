"""The QA's open decisions, as decided on 2026-10-30."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import SensorHeartbeat, Tenant


def _acme(db):
    return db.query(Tenant).filter(Tenant.slug == "acme").one()


# --- the full org export needs a signed-in admin, not an API key --------------------------

def test_org_export_refuses_api_keys(client, raw_client):
    for scope in ("console_read", "console_write"):
        key = client.post("/api/apikeys", json={"label": scope, "scope": scope}).json()["token"]
        r = raw_client.get("/api/export/tenant", headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 403 and "session" in r.json()["detail"]
    assert client.get("/api/export/tenant").status_code == 200        # the admin's session
    # The findings export (SIEM pull) still takes a console key.
    key = client.post("/api/apikeys", json={"label": "siem", "scope": "console_read"}).json()["token"]
    assert raw_client.get("/api/export/findings",
                          headers={"Authorization": f"Bearer {key}"}).status_code == 200


# --- one heartbeat row per client ----------------------------------------------------------

def _mcp(raw_client, key, ua):
    return raw_client.post("/api/ingest/mcp", headers={"X-Palivane-Token": key, "User-Agent": ua},
                           json={"server": "", "tool": "Bash", "args_text": "git status",
                                 "user": "dev@acme.com"})


def test_two_clients_reporting_one_tool_are_two_sensors(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "fleet", "scope": "ingest"}).json()["token"]
    assert _mcp(raw_client, key, "palivane-hook/1.2.0 (claude-code/2.1.4)").status_code == 200
    assert _mcp(raw_client, key, "palivane-mcp/0.9.2 (cursor/1.7)").status_code == 200
    assert _mcp(raw_client, key, "").status_code == 200                # no UA: no third row
    db = db_factory()
    try:
        rows = (db.query(SensorHeartbeat)
                  .filter(SensorHeartbeat.actor == "dev@acme.com", SensorHeartbeat.tool == "Bash")
                  .all())
        assert sorted(r.client for r in rows) == ["palivane-hook", "palivane-mcp"]
        assert sum(r.count for r in rows) == 3
    finally:
        db.close()


def test_a_legacy_row_is_adopted_not_duplicated(client, raw_client, db_factory):
    from datetime import datetime
    db = db_factory()
    db.add(SensorHeartbeat(tenant_id=_acme(db).id, actor="dev@acme.com", plane="mcp", tool="Bash",
                           client="", count=5, first_seen=datetime.utcnow(),
                           last_seen=datetime.utcnow()))
    db.commit(); db.close()
    key = client.post("/api/apikeys", json={"label": "fleet", "scope": "ingest"}).json()["token"]
    _mcp(raw_client, key, "palivane-hook/1.2.0 (claude-code/2.1.4)")
    db = db_factory()
    try:
        rows = db.query(SensorHeartbeat).filter(SensorHeartbeat.tool == "Bash").all()
        assert [(r.client, r.count) for r in rows] == [("palivane-hook", 6)]
    finally:
        db.close()


# --- over the ingest quota: fail open, but a confirmed leak still blocks --------------------

def _over_quota(db_factory):
    db = db_factory()
    _acme(db).ingest_rate_limit = 1
    db.commit(); db.close()


def _key_value():
    return "AKIA" + "".join("QWERTYUIOPASDFGH"[(i * 7) % 16] for i in range(16))


def test_over_quota_still_blocks_a_confirmed_leak(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "dev@acme.com",
                                            "scope": "ingest"}).json()["token"]
    _over_quota(db_factory)
    h = {"X-Palivane-Token": key}
    raw_client.post("/api/ingest/ai-usage", headers=h,
                    json={"content": "warm up", "destination": "chatgpt.com"})   # uses the 1/min
    leak = raw_client.post("/api/ingest/ai-usage", headers=h,
                           json={"content": f"deploy with {_key_value()}", "destination": "chatgpt.com"})
    assert leak.status_code == 200, leak.text
    body = leak.json()
    assert body["quota_exceeded"] is True and body["force_block"] is True and body["action"] == "block"
    assert _key_value() not in leak.text
    benign = raw_client.post("/api/ingest/ai-usage", headers=h,
                             json={"content": "summarize this", "destination": "chatgpt.com"}).json()
    assert benign["quota_exceeded"] is True and benign["action"] == "allow"
    mcp = raw_client.post("/api/ingest/mcp", headers=h,
                          json={"server": "s", "tool": "Bash",
                                "args_text": f"export K={_key_value()}"}).json()
    assert mcp["quota_exceeded"] is True and mcp["force_block"] is True


def test_other_capture_endpoints_still_429_over_quota(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "ext", "scope": "ingest"}).json()["token"]
    _over_quota(db_factory)
    h = {"X-Palivane-Token": key}
    raw_client.post("/api/ingest/ai-usage", headers=h, json={"content": "x", "destination": "d"})
    r = raw_client.post("/api/exception-request", headers=h, json={"reason": "x"})
    assert r.status_code == 429


# --- SSO keeps working after a plan downgrade -------------------------------------------------

def test_sso_sign_in_is_not_plan_gated(client, db_factory, monkeypatch):
    from app import oidc
    assert client.put("/api/oidc", json={"issuer": "https://idp.example.com", "client_id": "c",
                                         "client_secret": "s", "enabled": True}).status_code == 200
    db = db_factory()
    _acme(db).plan = "free"
    db.commit(); db.close()
    monkeypatch.setattr(oidc, "discover", lambda issuer: {
        "authorization_endpoint": "https://idp.example.com/authorize"})
    r = TestClient(app).get("/api/auth/oidc/acme/login", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"].startswith("https://idp.example.com/")


# --- the weekly report reaches the admins it missed -----------------------------------------

def test_weekly_report_retries_only_the_missed_admins(client, db_factory, monkeypatch):
    from app import alerts
    from app import email as email_mod
    from app.models import User
    client.post("/api/users", json={"email": "admin2@acme.com", "password": "second-admin-1",
                                    "role": "admin"})
    db = db_factory()
    t = _acme(db)
    t.weekly_report, t.weekly_report_last = True, None
    db.commit()
    assert db.query(User).filter(User.role == "admin", User.active.is_(True)).count() == 2
    db.close()

    sent, down = [], {"admin2@acme.com"}
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "send", lambda *a, **k: None)
    monkeypatch.setattr(email_mod, "send_now",
                        lambda to, s, b: (to not in down) and (sent.append(to) or True))
    db = db_factory()
    try:
        assert alerts.run_weekly_reports(db) == 1                     # the week went out
        assert sent == ["admin@acme.com"]
        assert db.query(Tenant).filter(Tenant.slug == "acme").one().weekly_report_retry["to"] == \
            ["admin2@acme.com"]
        down.clear()
        alerts.run_weekly_reports(db)                                 # next tick: just the retry
        assert sent == ["admin@acme.com", "admin2@acme.com"]
        db.expire_all()
        assert db.query(Tenant).filter(Tenant.slug == "acme").one().weekly_report_retry is None
    finally:
        db.close()


def test_weekly_retry_gives_up(client, db_factory, monkeypatch):
    from app import alerts
    from app import email as email_mod
    monkeypatch.setattr(email_mod, "send_now", lambda *a: False)
    db = db_factory()
    try:
        t = _acme(db)
        t.weekly_report_retry = {"to": ["gone@acme.com"], "body": "b", "tries": 0}
        db.commit()
        for _ in range(alerts._WEEKLY_RETRIES):
            alerts._retry_weekly(db, t, email_mod)
        assert t.weekly_report_retry is None
    finally:
        db.close()
