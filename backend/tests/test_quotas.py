"""Per-tenant resource quotas: user/API-key caps at creation, daily ingest cap on top of
the per-minute rate, tenant overrides, and console visibility via /api/usage."""

from __future__ import annotations

import app.metering as metering


def _set_quota(monkeypatch, **kw):
    for name, val in kw.items():
        monkeypatch.setattr(metering.settings, f"quota_{name}", val)


def test_user_quota_blocks_creation(client, monkeypatch):
    _set_quota(monkeypatch, users=2)
    ok = client.post("/api/users", json={"email": "two@acme.com",
                                         "password": "password123", "role": "analyst"})
    assert ok.status_code == 200          # 2nd user fits
    over = client.post("/api/users", json={"email": "three@acme.com",
                                           "password": "password123", "role": "analyst"})
    assert over.status_code == 403 and "quota" in over.json()["detail"]


def test_user_quota_blocks_join_approval(client, raw_client, monkeypatch):
    import app.domains as domains
    d = client.post("/api/domains", json={"domain": "acme.com"}).json()
    monkeypatch.setattr(domains, "_lookup_txt",
                        lambda name: [f"palivane-domain-verify={d['token']}"])
    client.post(f"/api/domains/{d['id']}/verify")
    raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "late@acme.com", "password": "password123"})
    rid = client.get("/api/join-requests").json()["requests"][0]["id"]
    _set_quota(monkeypatch, users=1)      # tenant already has its admin
    r = client.post(f"/api/join-requests/{rid}/approve")
    assert r.status_code == 403 and "quota" in r.json()["detail"]


def test_api_key_quota_blocks_create_and_enroll(client, raw_client, monkeypatch):
    _set_quota(monkeypatch, api_keys=1)
    assert client.post("/api/apikeys", json={"label": "a", "actor": "a@acme.com"}).status_code == 200
    over = client.post("/api/apikeys", json={"label": "b", "actor": "b@acme.com"})
    assert over.status_code == 403 and "quota" in over.json()["detail"]
    # device self-enroll counts against the same cap
    et = client.post("/api/enroll/tokens", json={"label": "fleet"}).json()["token"]
    r = raw_client.post("/api/enroll", json={"token": et, "device": "laptop-1"})
    assert r.status_code == 403
    # revoking a key frees a slot for enrollment
    kid = client.get("/api/apikeys").json()["api_keys"][0]["id"]
    client.delete(f"/api/apikeys/{kid}")
    assert raw_client.post("/api/enroll", json={"token": et, "device": "laptop-1"}).status_code == 200


def test_daily_ingest_quota(client, raw_client, monkeypatch):
    _set_quota(monkeypatch, ingest_per_day=2)
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    payload = {"content": "hello", "destination": "https://chatgpt.com/"}
    hdrs = {"X-Palivane-Token": key}
    assert raw_client.post("/api/ingest/ai-usage", json=payload, headers=hdrs).status_code == 200
    assert raw_client.post("/api/ingest/ai-usage", json=payload, headers=hdrs).status_code == 200
    over = raw_client.post("/api/ingest/ai-usage", json=payload, headers=hdrs)
    assert over.status_code == 429 and "daily" in over.json()["detail"]


def test_tenant_override_beats_global(client, db_factory, monkeypatch):
    _set_quota(monkeypatch, users=1)
    db = db_factory()
    from app.models import Tenant
    db.query(Tenant).filter(Tenant.id == 1).update({"quota_users": 3})
    db.commit()
    db.close()
    r = client.post("/api/users", json={"email": "extra@acme.com",
                                        "password": "password123", "role": "analyst"})
    assert r.status_code == 200           # override (3) wins over global (1)


def test_usage_reports_quotas(client, monkeypatch):
    _set_quota(monkeypatch, users=25, api_keys=100, ingest_per_day=50000)
    q = client.get("/api/usage").json()["quotas"]
    assert q == {"users": 25, "api_keys": 100, "ingest_per_day": 50000, "ingest_today": 0}
