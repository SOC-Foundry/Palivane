"""The personal tier: a one-person workspace from signup, free, no clock, quotas of one."""
from __future__ import annotations

from app.models import Tenant


def test_personal_signup_makes_a_one_person_workspace(raw_client, db_factory, monkeypatch):
    from app import auth as auth_mod
    monkeypatch.setattr(auth_mod.settings, "allow_signup", True)
    monkeypatch.setattr(auth_mod.settings, "trial_days", 14)
    r = raw_client.post("/api/auth/signup", json={"email": "sam.lee@example.net", "password": "password123", "plan": "personal"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("access_token") or body.get("status") == "verify_email"
    t = db_factory().query(Tenant).filter(Tenant.slug.like("sam%")).one()
    assert t.plan == "personal" and t.trial_ends_at is None
    assert t.name == "Sam Lee"


def test_personal_quota_is_one_user(client, raw_client, db_factory, monkeypatch):
    from app import auth as auth_mod
    monkeypatch.setattr(auth_mod.settings, "allow_signup", True)
    r = raw_client.post("/api/auth/signup", json={"email": "solo@example.net", "password": "password123", "plan": "personal", "org_name": "Solo Shop"})
    assert r.status_code == 200, r.text
    tok = r.json().get("access_token")
    if not tok:   # the email plane is on in this environment: verify first
        return
    h = {"Authorization": f"Bearer {tok}"}
    me = raw_client.get("/api/auth/me", headers=h).json()
    assert me["tenant"]["plan"] == "personal"
    add = raw_client.post("/api/users", json={"email": "second@example.net", "password": "password123", "role": "member"}, headers=h)
    assert add.status_code in (402, 403), add.text


def test_org_signup_still_needs_a_name(raw_client, monkeypatch):
    from app import auth as auth_mod
    monkeypatch.setattr(auth_mod.settings, "allow_signup", True)
    r = raw_client.post("/api/auth/signup", json={"email": "x@example.net", "password": "password123"})
    assert r.status_code == 422
    assert raw_client.post("/api/auth/signup", json={"email": "x@example.net", "password": "password123", "plan": "enterprise"}).status_code == 422


def test_personal_plan_is_listed_and_not_purchasable():
    from app.plans import PLANS, PURCHASABLE
    assert PLANS["personal"]["quotas"]["users"] == 1 and "device_setup" in PLANS["personal"]["features"]
    assert "personal" not in PURCHASABLE
