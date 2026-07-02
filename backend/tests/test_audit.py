"""Per-tenant admin audit log: actions are recorded, readable, admin-only, tenant-scoped."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import users as users_cli
from app.main import app


def _actions(client, **params):
    return [e["action"] for e in client.get("/api/audit", params=params).json()["entries"]]


def test_admin_actions_are_recorded(client):
    client.post("/api/users", json={"email": "a@acme.com", "password": "password123", "role": "analyst"})
    client.post("/api/apikeys", json={"label": "k", "actor": "svc"})
    client.put("/api/upstreams/openai", json={"base_url": "https://x", "key": "sk"})
    client.patch("/api/tenant", json={"rate_limit": 5})

    actions = _actions(client)
    for a in ("user.create", "apikey.create", "upstream.set", "tenant.update"):
        assert a in actions


def test_audit_entry_has_actor_and_target(client):
    client.post("/api/users", json={"email": "b@acme.com", "password": "password123", "role": "analyst"})
    entry = next(e for e in client.get("/api/audit").json()["entries"] if e["action"] == "user.create")
    assert entry["actor"] == "admin@acme.com"
    assert entry["target"] == "b@acme.com"
    assert entry["detail"]["role"] == "analyst"


def test_audit_filter_by_action(client):
    client.post("/api/apikeys", json={"label": "k1", "actor": "s"})
    client.post("/api/users", json={"email": "c@acme.com", "password": "password123"})
    only = client.get("/api/audit", params={"action": "apikey.create"}).json()["entries"]
    assert only and all(e["action"] == "apikey.create" for e in only)


def test_audit_is_admin_only(raw_client):
    assert raw_client.get("/api/audit").status_code == 401


def test_audit_is_tenant_scoped(client, db_factory):
    # Another tenant's admin action must not appear in acme's audit log.
    db = db_factory()
    users_cli.create_tenant(db, "globex", "Globex")
    users_cli.create_user(db, "globex", "admin@globex.com", "password123", "admin")
    db.close()
    gx = TestClient(app)
    gx.headers.update({"Authorization": "Bearer " + gx.post(
        "/api/auth/login", json={"email": "admin@globex.com", "password": "password123"}).json()["access_token"]})
    gx.post("/api/apikeys", json={"label": "gxkey", "actor": "s"})

    acme_targets = [e["target"] for e in client.get("/api/audit").json()["entries"]]
    assert "gxkey" not in acme_targets
    assert "gxkey" in [e["target"] for e in gx.get("/api/audit").json()["entries"]]