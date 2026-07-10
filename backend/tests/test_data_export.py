"""Full per-tenant data export: completeness, tenant isolation, no-secrets, content flag."""

from __future__ import annotations

import json

from app import users as users_cli


def _seed_beta(db_factory):
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta")
    users_cli.create_user(db, "beta", "admin@beta.com", "password123", "admin")
    db.close()


def test_export_is_complete_and_scoped(client):
    client.post("/api/apikeys", json={"label": "k", "actor": "svc@acme.com"})
    client.post("/api/analyze", json={"content": "hello world", "persist": True})
    r = client.get("/api/export/tenant")
    assert r.status_code == 200
    assert r.headers["content-disposition"].endswith("warden-export-acme.json")
    doc = r.json()
    assert doc["tenant"]["slug"] == "acme"
    assert doc["counts"]["findings"] >= 1 and doc["counts"]["api_keys"] >= 1
    assert any(u["email"] == "admin@acme.com" for u in doc["users"])
    assert {"users", "api_keys", "enrollment_tokens", "findings", "audit_log",
            "upstreams", "sso", "agents", "agent_roles", "policy_overrides",
            "discovered_usage"} <= set(doc)


def test_export_includes_agents_without_secrets(client, db_factory):
    from app.models import Agent
    db = db_factory()
    tid = db.query(__import__("app.models", fromlist=["Tenant"]).Tenant).first().id
    db.add(Agent(tenant_id=tid, name="bot", prefix="ag_z", token_hash="SECRETHASH"))
    db.commit(); db.close()
    blob = client.get("/api/export/tenant").text
    assert "SECRETHASH" not in blob            # token_hash never exported
    doc = json.loads(blob)
    assert any(a["name"] == "bot" for a in doc["agents"])


def test_export_excludes_other_tenants(client, db_factory):
    _seed_beta(db_factory)
    client.post("/api/analyze", json={"content": "acme secret note", "persist": True})
    doc = client.get("/api/export/tenant").json()
    # Only acme's users/findings; beta must be absent.
    assert all(u["tenant_id"] == doc["tenant"]["id"] for u in doc["users"])
    assert not any(u["email"] == "admin@beta.com" for u in doc["users"])


def test_export_never_leaks_secrets(client):
    # Give the tenant an upstream with a key + a user with a password → none may appear.
    client.put("/api/upstreams/openai", json={"base_url": "https://api.openai.com/v1", "key": "sk-supersecret123"})
    blob = client.get("/api/export/tenant").text
    for needle in ("password_hash", "token_hash", "mfa_secret", "key_encrypted",
                   "client_secret", "sk-supersecret123", "enc:v1:"):
        assert needle not in blob, needle
    # The upstream is still represented — just without the key.
    doc = json.loads(blob)
    assert doc["upstreams"] and doc["upstreams"][0]["has_key"] is True


def test_export_content_flag(client):
    client.post("/api/analyze", json={"content": "TOKEN abcdef012345 in here", "persist": True})
    summary = client.get("/api/export/tenant").json()
    assert "content" not in summary["findings"][0]           # default: summaries only
    full = client.get("/api/export/tenant?include_content=true").json()
    assert "content" in full["findings"][0] and "signals" in full["findings"][0]


def test_export_admin_only(client, db_factory):
    assert __import__("app.main", fromlist=["app"]).app  # ensure app importable
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    tok = client.post("/api/auth/login",
                      json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    assert client.get("/api/export/tenant", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_export_requires_auth(raw_client):
    assert raw_client.get("/api/export/tenant").status_code == 401
