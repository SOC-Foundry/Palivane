"""Low-severity problems the QA re-run found (2026-10-30)."""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app.main import app

REDIRECT = "https://claude.ai/cb"


# --- Authorized apps: a row is one person's approval -------------------------------------

def _grant(client_or_raw, raw_client, headers=None):
    """Register an app and have the caller approve it; returns (client_id, access token)."""
    cid = raw_client.post("/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    code = client_or_raw.post("/api/oauth/consent", headers=headers or {}, json={
        "client_id": cid, "redirect_uri": REDIRECT, "code_challenge": challenge,
    }).json()["redirect_to"].split("code=")[1].split("&")[0]
    tok = raw_client.post("/token", data={"grant_type": "authorization_code", "code": code,
                                          "redirect_uri": REDIRECT, "client_id": cid,
                                          "code_verifier": verifier}).json()["access_token"]
    return cid, tok


def _consent_again(client, raw_client, cid, headers):
    verifier = "u" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    code = client.post("/api/oauth/consent", headers=headers, json={
        "client_id": cid, "redirect_uri": REDIRECT, "code_challenge": challenge,
    }).json()["redirect_to"].split("code=")[1].split("&")[0]
    return raw_client.post("/token", data={"grant_type": "authorization_code", "code": code,
                                           "redirect_uri": REDIRECT, "client_id": cid,
                                           "code_verifier": verifier}).json()["access_token"]


def test_revoking_one_row_leaves_other_approvers_connected(client, raw_client, db_factory):
    from app.mcp_remote import _oauth_user_id
    client.post("/api/users", json={"email": "an@acme.com", "password": "analyst-pass-123",
                                    "role": "analyst"})
    an = TestClient(app).post("/api/auth/login", json={"email": "an@acme.com",
                                                       "password": "analyst-pass-123"})
    an_h = {"Authorization": f"Bearer {an.json()['access_token']}"}
    cid, admin_tok = _grant(client, raw_client)
    analyst_tok = _consent_again(client, raw_client, cid, an_h)

    rows = client.get("/api/oauth/grants").json()["grants"]
    mine = next(g for g in rows if g["client_id"] == cid and g["granted_by"] == "admin@acme.com")
    assert "user_id" in mine
    assert client.delete(f"/api/oauth/grants/{cid}?user_id={mine['user_id']}").status_code == 200

    db = db_factory()
    try:
        assert _oauth_user_id(admin_tok, db) is None         # the admin's own grant is gone
        assert _oauth_user_id(analyst_tok, db) is not None   # the analyst's is untouched
    finally:
        db.close()
    # Without user_id an admin still cuts the app off for everyone.
    assert client.delete(f"/api/oauth/grants/{cid}").status_code == 200
    db = db_factory()
    try:
        assert _oauth_user_id(analyst_tok, db) is None
    finally:
        db.close()


# --- OAuth metadata and /revoke ----------------------------------------------------------

def test_discovery_lists_public_client_auth(raw_client):
    doc = raw_client.get("/.well-known/oauth-authorization-server").json()
    assert "none" in doc["token_endpoint_auth_methods_supported"]
    assert "none" in doc["revocation_endpoint_auth_methods_supported"]
    assert doc["token_endpoint"].endswith("/token")              # the rest is intact


def test_revoke_without_client_id_is_invalid_client(raw_client):
    r = raw_client.post("/revoke", data={"token": "pat_x"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_mcp_401_mentions_oauth(raw_client):
    r = raw_client.post("/api/mcp/", json={})
    assert r.status_code == 401 and "OAuth" in r.text and "console-scoped" in r.text


# --- CLI downloads keep their own content type --------------------------------------------

def test_script_types():
    from app.distribution import _script_type
    assert _script_type("palivane-desktop.ps1") == "text/plain"
    assert _script_type("palivane_addon.py") == "text/x-python"
    assert _script_type("palivane-hook") == "text/x-shellscript"


# --- SSO -----------------------------------------------------------------------------------

def test_saml_accepts_assertions_without_an_attribute_statement():
    from types import SimpleNamespace

    from app.saml import _settings
    cfg = SimpleNamespace(idp_entity_id="e", idp_sso_url="https://idp.example.com/sso",
                          idp_x509_cert="x")
    assert _settings(cfg, "sp", "https://sp/acs")["security"]["wantAttributeStatement"] is False


def test_an_unresolvable_issuer_says_so(monkeypatch):
    import socket

    from app import netguard, oidc
    monkeypatch.setattr(netguard, "is_safe_url", lambda u: False)

    def nxdomain(*a, **k):
        raise socket.gaierror("not found")

    monkeypatch.setattr(socket, "getaddrinfo", nxdomain)
    with pytest.raises(oidc.OIDCError, match="could not resolve"):
        oidc._safe("https://no-such-idp.example.com/.well-known/openid-configuration")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [("x",)])
    with pytest.raises(oidc.OIDCError, match="non-public"):
        oidc._safe("https://internal.example.com/")


# --- the operator CLI ----------------------------------------------------------------------

def test_negative_trial_days_is_a_clean_cli_error(monkeypatch):
    from app import users
    from app.models import Tenant
    t = Tenant(name="t", slug="t", plan="free")
    monkeypatch.setattr(users, "_get_tenant", lambda db, slug: t)
    with pytest.raises(SystemExit) as e:
        users.main(["set-plan", "--tenant", "t", "--plan", "trial", "--trial-days", "-5"])
    assert str(e.value).startswith("error:") and "trial_days" in str(e.value)
    assert t.plan == "free"                                  # refused before anything changed
