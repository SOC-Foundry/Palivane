"""Per-tenant OIDC SSO: config API, auth-code redirect, and callback provisioning.

The IdP boundary (discovery/token-exchange/ID-token validation) is mocked, so no real
identity provider is needed — the flow, state handling, and user provisioning are tested."""

from __future__ import annotations

import app.oidc as oidc_mod
from app.security import create_token

META = {"authorization_endpoint": "https://idp.test/auth",
        "token_endpoint": "https://idp.test/token",
        "jwks_uri": "https://idp.test/jwks"}


def _configure(client, **over):
    body = {"issuer": "https://idp.test", "client_id": "cid",
            "client_secret": "csecret", "enabled": True}
    body.update(over)
    return client.put("/api/oidc", json=body)


def test_oidc_config_crud_hides_secret(client):
    r = _configure(client)
    assert r.status_code == 200
    b = r.json()
    assert b["enabled"] and b["secret_set"] and b["issuer"] == "https://idp.test"
    assert "client_secret" not in b and "client_secret_encrypted" not in b
    got = client.get("/api/oidc").json()
    assert got["secret_set"] and got["client_id"] == "cid" and "client_secret" not in got
    assert client.delete("/api/oidc").json()["configured"] is False


def test_oidc_admin_only(raw_client):
    assert raw_client.get("/api/oidc").status_code == 401
    assert raw_client.put("/api/oidc", json={"issuer": "x"}).status_code == 401


def test_login_redirects_to_idp(client, monkeypatch):
    _configure(client)
    monkeypatch.setattr(oidc_mod, "discover", lambda issuer: META)
    r = client.get("/api/auth/oidc/acme/login", follow_redirects=False)
    assert r.status_code == 307
    loc = r.headers["location"]
    assert loc.startswith("https://idp.test/auth?")
    assert "client_id=cid" in loc and "state=" in loc and "nonce=" in loc
    assert "callback" in loc  # redirect_uri points back at our callback


def test_login_404_when_not_configured(client):
    assert client.get("/api/auth/oidc/acme/login", follow_redirects=False).status_code == 404


def test_callback_provisions_user_and_issues_working_session(client, monkeypatch):
    _configure(client, auto_provision=True)   # this test exercises provisioning explicitly
    monkeypatch.setattr(oidc_mod, "discover", lambda i: META)
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **k: {"id_token": "idtok"})
    monkeypatch.setattr(oidc_mod, "validate_id_token", lambda *a, **k: {"email": "sso@acme.com"})
    state = create_token({"typ": "oidc_state", "org": "acme", "nonce": "N"}, ttl=600)

    r = client.get(f"/api/auth/oidc/acme/callback?code=xyz&state={state}", follow_redirects=False)
    assert r.status_code == 303
    assert "#sso_token=" in r.headers["location"]
    token = r.headers["location"].split("#sso_token=")[1]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "sso@acme.com"
    assert me.json()["user"]["role"] == "analyst"     # auto-provisioned as analyst


def test_callback_rejects_bad_state(client, monkeypatch):
    _configure(client)
    monkeypatch.setattr(oidc_mod, "discover", lambda i: META)
    r = client.get("/api/auth/oidc/acme/callback?code=x&state=garbage", follow_redirects=False)
    assert r.status_code == 400


def test_callback_without_autoprovision_rejects_unknown_email(client, monkeypatch):
    _configure(client, auto_provision=False)
    monkeypatch.setattr(oidc_mod, "discover", lambda i: META)
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **k: {"id_token": "x"})
    monkeypatch.setattr(oidc_mod, "validate_id_token", lambda *a, **k: {"email": "stranger@acme.com"})
    state = create_token({"typ": "oidc_state", "org": "acme", "nonce": "N"}, ttl=600)
    r = client.get(f"/api/auth/oidc/acme/callback?code=x&state={state}", follow_redirects=False)
    assert r.status_code == 403


def test_callback_enforces_allowed_domain(client, monkeypatch):
    _configure(client, allowed_domain="acme.com")
    monkeypatch.setattr(oidc_mod, "discover", lambda i: META)
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **k: {"id_token": "x"})
    monkeypatch.setattr(oidc_mod, "validate_id_token", lambda *a, **k: {"email": "user@evil.com"})
    state = create_token({"typ": "oidc_state", "org": "acme", "nonce": "N"}, ttl=600)
    r = client.get(f"/api/auth/oidc/acme/callback?code=x&state={state}", follow_redirects=False)
    assert r.status_code == 403

def test_oidc_auto_provision_defaults_off(client):
    # Safe default: a new SSO config does NOT auto-create accounts unless opted in.
    b = _configure(client).json()
    assert b["auto_provision"] is False
