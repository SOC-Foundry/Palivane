"""Accounts and identity fixes from the deep QA (M4, M5, M12, M13, M15, M19)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.models import AuditLog, LoginAttempt, Tenant, User
from app.security import hash_password


def _acme(db):
    return db.query(Tenant).filter(Tenant.slug == "acme").one()


# --- M4: demo visits and signups have their own throttle budget ----------------------------

def test_demo_and_signup_attempts_do_not_lock_out_login(client, db_factory):
    db = db_factory()
    for kind in ("demo", "signup", "forgot"):
        for _ in range(25):
            db.add(LoginAttempt(email="__demo__" if kind == "demo" else "x@y.com",
                                ip="testclient", kind=kind))
    db.commit(); db.close()
    r = TestClient(app).post("/api/auth/login",
                             json={"email": "admin@acme.com", "password": "password123"})
    assert r.status_code == 200, r.text


def test_failed_logins_still_throttle_by_ip(client, db_factory, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "login_ip_max_fails", 3)
    raw = TestClient(app)
    for i in range(3):
        raw.post("/api/auth/login", json={"email": f"nobody{i}@acme.com", "password": "nope"})
    r = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"})
    assert r.status_code == 429


# --- M5: two look-alike accounts elsewhere can't crowd out the real one --------------------

def test_login_finds_the_real_account_behind_two_others(client, db_factory):
    db = db_factory()
    for slug in ("squat-a", "squat-b"):
        t = Tenant(name=slug, slug=slug)
        db.add(t); db.flush()
        db.add(User(tenant_id=t.id, email="victim@corp.example", role="admin",
                    password_hash=hash_password("attacker-pass-1"), email_verified=True))
    real = Tenant(name="real", slug="real-corp")
    db.add(real); db.flush()
    db.add(User(tenant_id=real.id, email="victim@corp.example", role="admin",
                password_hash=hash_password("victims-own-pass"), email_verified=True))
    db.commit(); db.close()
    r = TestClient(app).post("/api/auth/login", json={"email": "victim@corp.example",
                                                      "password": "victims-own-pass"})
    assert r.status_code == 200, r.text


# --- M12: removing the last admin is refused even when the count raced ---------------------

def test_post_write_recount_refuses_zero_admins(client, db_factory):
    from app.auth import _still_has_admin
    db = db_factory()
    try:
        tid = _acme(db).id
        for u in db.query(User).filter(User.tenant_id == tid, User.role == "admin"):
            u.active = False
        with pytest.raises(HTTPException) as e:
            _still_has_admin(db, tid)
        assert e.value.status_code == 400
        assert db.query(User).filter(User.tenant_id == tid, User.role == "admin",
                                     User.active.is_(True)).count() >= 1   # rolled back
    finally:
        db.close()


def _scim(client):
    return {"Authorization": f"Bearer {client.post('/api/scim/token').json()['token']}"}


def test_scim_deactivate_rechecks_after_a_stale_count(client, monkeypatch):
    from app import scim
    h = _scim(client)
    admin_id = client.get('/scim/v2/Users?filter=userName eq "admin@acme.com"',
                          headers=h).json()["Resources"][0]["id"]
    real = scim._active_admins
    calls = {"n": 0}

    def stale(db, tid):                       # first count is the one that raced: it saw 2
        calls["n"] += 1
        return 2 if calls["n"] == 1 else real(db, tid)

    monkeypatch.setattr(scim, "_active_admins", stale)
    r = client.delete(f"/scim/v2/Users/{admin_id}", headers=h)
    assert r.status_code == 409
    monkeypatch.setattr(scim, "_active_admins", real)
    assert client.get(f"/scim/v2/Users/{admin_id}", headers=h).json()["active"] is True


# --- M13: a refused SCIM PatchOp applies nothing -------------------------------------------

def test_failed_patchop_rolls_back_its_earlier_operations(client, db_factory):
    h = _scim(client)
    uid = client.post("/scim/v2/Users", headers=h, json={"userName": "pat@acme.com"}).json()["id"]
    client.post("/scim/v2/Users", headers=h, json={"userName": "taken@acme.com"})
    r = client.patch(f"/scim/v2/Users/{uid}", headers=h, json={"Operations": [
        {"op": "replace", "path": "active", "value": False},
        {"op": "replace", "path": "userName", "value": "taken@acme.com"}]})
    assert r.status_code == 409
    after = client.get(f"/scim/v2/Users/{uid}", headers=h).json()
    assert after["active"] is True and after["userName"] == "pat@acme.com"
    db = db_factory()
    try:
        assert not db.query(AuditLog).filter(AuditLog.action == "scim.user_deactivated").count()
    finally:
        db.close()


def test_successful_patchop_is_still_audited(client, db_factory):
    h = _scim(client)
    uid = client.post("/scim/v2/Users", headers=h, json={"userName": "ok@acme.com"}).json()["id"]
    r = client.patch(f"/scim/v2/Users/{uid}", headers=h, json={"Operations": [
        {"op": "replace", "path": "active", "value": False}]})
    assert r.status_code == 200
    db = db_factory()
    try:
        actions = {a for (a,) in db.query(AuditLog.action)}
        assert {"scim.user_created", "scim.user_deactivated"} <= actions
    finally:
        db.close()


# --- M15: SSO and SCIM provisioning respect the users quota ---------------------------------

def _full(db_factory):
    db = db_factory()
    t = _acme(db)
    t.quota_users = db.query(User).filter(User.tenant_id == t.id).count()
    db.commit(); db.close()


def test_scim_create_respects_the_seat_quota(client, db_factory):
    h = _scim(client)
    _full(db_factory)
    r = client.post("/scim/v2/Users", headers=h, json={"userName": "seat@acme.com"})
    assert r.status_code == 403 and "quota" in r.json()["detail"]


def test_sso_auto_provision_respects_the_seat_quota(client, db_factory):
    from app.auth import _sso_complete
    _full(db_factory)
    db = db_factory()
    try:
        with pytest.raises(HTTPException) as e:
            _sso_complete(db, _acme(db), "newcomer@acme.com", True, "", "https://x")
        assert e.value.status_code == 403
        assert not db.query(User).filter(User.email == "newcomer@acme.com").count()
    finally:
        db.close()


# --- M19: no reset mail for an unconfirmed signup; signup checks the address ----------------

def test_forgot_skips_unverified_accounts(client, db_factory, monkeypatch):
    from app import email as email_mod
    sent = []
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "send", lambda to, *a, **k: sent.append(to))
    db = db_factory()
    t = Tenant(name="Totally Real Bank", slug="squatter-org")
    db.add(t); db.flush()
    db.add(User(tenant_id=t.id, email="someone@corp.example", role="admin",
                password_hash=hash_password("whatever-123"), email_verified=False))
    db.commit(); db.close()
    TestClient(app).post("/api/auth/forgot", json={"email": "someone@corp.example"})
    assert sent == []
    TestClient(app).post("/api/auth/forgot", json={"email": "admin@acme.com"})
    assert sent == ["admin@acme.com"]


@pytest.mark.parametrize("email", ["nope", "a@b", "a b@c.com", "@b.com", "a@@b.com"])
def test_signup_rejects_malformed_email(email):
    r = TestClient(app).post("/api/auth/signup", json={"org_name": "Org", "email": email,
                                                       "password": "longenough1"})
    assert r.status_code == 422
