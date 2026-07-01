"""Auth + multi-tenant isolation through the HTTP API."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import users as users_cli
from app.main import app


def _login(c, email, pw):
    r = c.post("/api/auth/login", json={"email": email, "password": pw})
    return r


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _seed_two_tenants(db_factory):
    db = db_factory()
    users_cli.create_tenant(db, "acme", "Acme")
    users_cli.create_tenant(db, "globex", "Globex")
    users_cli.create_user(db, "acme", "admin@acme.com", "password123", "admin")
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    users_cli.create_user(db, "globex", "admin@globex.com", "password123", "admin")
    db.close()


def test_unauthenticated_requests_are_rejected(raw_client):
    assert raw_client.get("/api/findings").status_code == 401
    assert raw_client.get("/api/stats").status_code == 401
    assert raw_client.post("/api/analyze", json={"content": "hi"}).status_code == 401


def test_login_and_me(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    r = _login(c, "admin@acme.com", "password123")
    assert r.status_code == 200
    me = c.get("/api/auth/me", headers=_auth(r.json()["access_token"])).json()
    assert me["user"]["email"] == "admin@acme.com"
    assert me["tenant"]["slug"] == "acme"


def test_bad_password_rejected(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    assert _login(c, "admin@acme.com", "nope").status_code == 401
    assert _login(c, "ghost@acme.com", "password123").status_code == 401


def test_tenant_isolation_of_findings(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    acme = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    globex = c.post("/api/auth/login", json={"email": "admin@globex.com", "password": "password123"}).json()["access_token"]

    # Acme analyzes-and-persists a finding.
    res = c.post("/api/analyze", headers=_auth(acme),
                 json={"content": "URGENT verify your account, confirm your password", "persist": True})
    fid = res.json()["finding_id"]
    assert fid is not None

    # Acme sees it; Globex does not.
    assert any(f["id"] == fid for f in c.get("/api/findings", headers=_auth(acme)).json()["findings"])
    assert c.get("/api/findings", headers=_auth(globex)).json()["findings"] == []
    # Direct fetch across tenants is a 404, not a leak.
    assert c.get(f"/api/findings/{fid}", headers=_auth(globex)).status_code == 404
    assert c.get(f"/api/findings/{fid}", headers=_auth(acme)).status_code == 200
    # Stats are scoped too.
    assert c.get("/api/stats", headers=_auth(globex)).json()["total"] == 0
    assert c.get("/api/stats", headers=_auth(acme)).json()["total"] == 1


def test_analyst_cannot_manage_users_admin_can(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    analyst = c.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    admin = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]

    body = {"email": "new@acme.com", "password": "password123", "role": "analyst"}
    assert c.post("/api/users", headers=_auth(analyst), json=body).status_code == 403
    assert c.post("/api/users", headers=_auth(admin), json=body).status_code == 200
    # New user lands in the admin's tenant.
    emails = {u["email"] for u in c.get("/api/users", headers=_auth(admin)).json()["users"]}
    assert "new@acme.com" in emails


def test_new_user_can_log_in(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    admin = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    c.post("/api/users", headers=_auth(admin),
           json={"email": "new@acme.com", "password": "password123", "role": "analyst"})
    assert _login(c, "new@acme.com", "password123").status_code == 200


def _uid(c, admin, email):
    users = c.get("/api/users", headers=_auth(admin)).json()["users"]
    return next(u["id"] for u in users if u["email"] == email)


def test_admin_can_promote_and_demote(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    admin = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    aid = _uid(c, admin, "analyst@acme.com")

    # Promote analyst -> admin, then demote back.
    r = c.patch(f"/api/users/{aid}", headers=_auth(admin), json={"role": "admin"})
    assert r.status_code == 200 and r.json()["role"] == "admin"
    r = c.patch(f"/api/users/{aid}", headers=_auth(admin), json={"role": "analyst"})
    assert r.status_code == 200 and r.json()["role"] == "analyst"


def test_disable_login_blocks_then_reenable(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    admin = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    aid = _uid(c, admin, "analyst@acme.com")

    assert c.patch(f"/api/users/{aid}", headers=_auth(admin), json={"active": False}).status_code == 200
    assert _login(c, "analyst@acme.com", "password123").status_code == 401
    assert c.patch(f"/api/users/{aid}", headers=_auth(admin), json={"active": True}).status_code == 200
    assert _login(c, "analyst@acme.com", "password123").status_code == 200


def test_cannot_demote_or_disable_self(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    admin = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    me = _uid(c, admin, "admin@acme.com")
    assert c.patch(f"/api/users/{me}", headers=_auth(admin), json={"role": "analyst"}).status_code == 400
    assert c.patch(f"/api/users/{me}", headers=_auth(admin), json={"active": False}).status_code == 400


def test_cannot_remove_last_admin(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    # globex has exactly one admin and no other users.
    admin = c.post("/api/auth/login", json={"email": "admin@globex.com", "password": "password123"}).json()["access_token"]
    me = _uid(c, admin, "admin@globex.com")
    # Even via a second admin, demoting the only remaining admin is blocked.
    assert c.patch(f"/api/users/{me}", headers=_auth(admin), json={"role": "analyst"}).status_code == 400


def test_user_management_is_tenant_scoped(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    acme = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    globex = c.post("/api/auth/login", json={"email": "admin@globex.com", "password": "password123"}).json()["access_token"]
    globex_uid = _uid(c, globex, "admin@globex.com")
    # Acme admin can't touch a Globex user.
    assert c.patch(f"/api/users/{globex_uid}", headers=_auth(acme), json={"role": "analyst"}).status_code == 404


def test_analyst_cannot_patch_users(db_factory):
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    admin = c.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["access_token"]
    analyst = c.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    aid = _uid(c, admin, "analyst@acme.com")
    assert c.patch(f"/api/users/{aid}", headers=_auth(analyst), json={"role": "admin"}).status_code == 403


def test_login_is_rate_limited_by_email(db_factory, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "login_max_fails", 3)
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    for _ in range(3):
        assert _login(c, "admin@acme.com", "wrong").status_code == 401
    # Further attempts are throttled — even with the *correct* password.
    assert _login(c, "admin@acme.com", "password123").status_code == 429
    # A different account is unaffected (its own email counter is at zero).
    assert _login(c, "admin@globex.com", "password123").status_code == 200


def test_login_is_rate_limited_by_ip_across_emails(db_factory, monkeypatch):
    # An attacker rotating emails from one IP is still throttled by the IP limit.
    from app.config import settings
    monkeypatch.setattr(settings, "login_max_fails", 100)   # don't trip the email limit
    monkeypatch.setattr(settings, "login_ip_max_fails", 3)
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    for e in ("a@x.com", "b@x.com", "c@x.com"):
        assert _login(c, e, "wrong").status_code == 401
    assert _login(c, "admin@acme.com", "password123").status_code == 429   # IP is blocked


def test_successful_login_clears_email_counter(db_factory, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "login_max_fails", 3)
    _seed_two_tenants(db_factory)
    c = TestClient(app)
    assert _login(c, "admin@acme.com", "wrong").status_code == 401
    assert _login(c, "admin@acme.com", "password123").status_code == 200   # clears counter
    assert _login(c, "admin@acme.com", "wrong").status_code == 401         # not locked (401, not 429)


# --- tenant-scoped login (multi-tenant hosting) --------------------------------------

def test_logout_all_revokes_existing_tokens(client):
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout-all").status_code == 200
    # The bearer token the client still holds is now revoked (token_version bumped).
    assert client.get("/api/auth/me").status_code == 401


def _legacy_pbkdf2(pw: str) -> str:
    import hashlib
    salt = b"0123456789abcdef"
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def test_legacy_pbkdf2_hash_logs_in_and_upgrades_to_argon2(db_factory):
    from app.models import Tenant, User
    db = db_factory()
    users_cli.create_tenant(db, "acme", "Acme")
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    db.add(User(tenant_id=tid, email="legacy@acme.com",
                password_hash=_legacy_pbkdf2("password123"), role="admin"))
    db.commit()
    db.close()

    c = TestClient(app)
    assert _login(c, "legacy@acme.com", "password123").status_code == 200

    db2 = db_factory()
    u = db2.query(User).filter(User.email == "legacy@acme.com").first()
    assert u.password_hash.startswith("$argon2")   # transparently upgraded on login
    db2.close()


def _seed_shared_email(db_factory):
    db = db_factory()
    users_cli.create_tenant(db, "acme", "Acme")
    users_cli.create_tenant(db, "globex", "Globex")
    users_cli.create_user(db, "acme", "shared@corp.com", "acme-pass-123", "admin")
    users_cli.create_user(db, "globex", "shared@corp.com", "globex-pass-456", "admin")
    db.close()


def test_ambiguous_email_across_tenants_requires_org(db_factory):
    _seed_shared_email(db_factory)
    c = TestClient(app)
    # Same email in two orgs, no org given -> refuse (never auto-pick a tenant).
    r = c.post("/api/auth/login", json={"email": "shared@corp.com", "password": "acme-pass-123"})
    assert r.status_code == 409


def test_org_scoped_login_selects_the_right_tenant(db_factory):
    _seed_shared_email(db_factory)
    c = TestClient(app)
    acme = c.post("/api/auth/login",
                  json={"email": "shared@corp.com", "password": "acme-pass-123", "org": "acme"})
    assert acme.status_code == 200
    me = c.get("/api/auth/me", headers=_auth(acme.json()["access_token"])).json()
    assert me["tenant"]["slug"] == "acme"
    # Right org, wrong-tenant password -> rejected.
    assert c.post("/api/auth/login",
                  json={"email": "shared@corp.com", "password": "globex-pass-456", "org": "acme"}
                  ).status_code == 401
    # Other org resolves independently.
    globex = c.post("/api/auth/login",
                    json={"email": "shared@corp.com", "password": "globex-pass-456", "org": "globex"})
    assert globex.status_code == 200
