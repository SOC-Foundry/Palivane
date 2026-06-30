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
