"""Adversarial checks on the OAuth grant. Each test is an attack, not a feature.

The consent step is where parameters cross a browser the user may not control and come back,
and the token is a credential that outlives the session that created it. These are the ways
someone would try to bend that.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app import users as users_cli
from app.main import app
from app.models import Finding, OAuthClient, OAuthToken as Row, Tenant, User
from app.oauth_provider import READ_SCOPE, _now

REDIRECT = "https://claude.ai/cb"


def _pkce():
    v = "v" * 64
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def _register(raw_client, uris=(REDIRECT,)):
    r = raw_client.post("/register", json={"redirect_uris": list(uris), "client_name": "Claude"})
    assert r.status_code in (200, 201), r.text
    return r.json()["client_id"]


def _grant(client, raw_client):
    """A full, legitimate grant. Returns the access token."""
    cid = _register(raw_client)
    verifier, challenge = _pkce()
    consent = client.post("/api/oauth/consent",
                          json={"client_id": cid, "redirect_uri": REDIRECT,
                                "code_challenge": challenge})
    assert consent.status_code == 200, consent.text
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]
    tok = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": cid, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    return tok.json()


# --- the one that matters most --------------------------------------------------------

def test_a_token_cannot_read_another_tenants_findings(client, raw_client, db_factory):
    """Cross-tenant isolation. A grant is scoped to the approving user's org, and a token
    that could read past it would be the worst possible bug in this system."""
    from app.mcp_remote import _CALLER, _OAUTH_USER, _read
    from app import main

    grant = _grant(client, raw_client)

    # A second org with a finding of its own, which the token must never see.
    db = db_factory()
    users_cli.create_tenant(db, "other", "Other Inc", plan="enterprise")
    other = db.query(Tenant).filter(Tenant.slug == "other").one()
    db.add(Finding(tenant_id=other.id, severity="critical", status="open",
                   surface="ai_usage", channel="llm", sender="them@other.example"))
    db.commit()
    other_id = other.id
    token_row = db.query(Row).filter(Row.kind == "access").one()
    assert token_row.tenant_id != other_id
    db.close()

    reset = _OAUTH_USER.set(token_row.user_id)
    creset = _CALLER.set(None)
    try:
        out = _read(main.list_findings, admin=False, limit=100)
        senders = {f.get("sender") for f in out["findings"]}
        assert "them@other.example" not in senders
        assert all(f.get("tenant_id", token_row.tenant_id) != other_id
                   for f in out["findings"])
    finally:
        _OAUTH_USER.reset(reset)
        _CALLER.reset(creset)


# --- token confusion --------------------------------------------------------------------

def test_a_refresh_token_is_not_an_access_token(client, raw_client):
    """They are both opaque strings from the same endpoint. Presenting the long-lived one
    as a bearer must fail, or refresh becomes a permanent access token."""
    grant = _grant(client, raw_client)
    r = raw_client.post("/api/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                           "params": {"protocolVersion": "2024-11-05",
                                                      "capabilities": {},
                                                      "clientInfo": {"name": "t", "version": "1"}}},
                        headers={"content-type": "application/json",
                                 "accept": "application/json, text/event-stream",
                                 "Authorization": f"Bearer {grant['refresh_token']}"})
    assert r.status_code == 401


def test_an_expired_access_token_stops_working(client, raw_client, db_factory):
    from datetime import timedelta
    from app.mcp_remote import _oauth_user_id
    grant = _grant(client, raw_client)
    db = db_factory()
    row = db.query(Row).filter(Row.kind == "access").one()
    row.expires_at = _now() - timedelta(seconds=1)
    db.commit()
    assert _oauth_user_id(grant["access_token"], db) is None
    db.close()


def test_the_grant_dies_with_the_user(client, raw_client, db_factory):
    """A token approved by someone since deactivated must stop working, exactly as a
    console key does — otherwise offboarding leaves a live credential behind."""
    from app.mcp_remote import _oauth_user_id
    grant = _grant(client, raw_client)
    db = db_factory()
    row = db.query(Row).filter(Row.kind == "access").one()
    assert _oauth_user_id(grant["access_token"], db) is not None
    db.get(User, row.user_id).active = False
    db.commit()
    assert _oauth_user_id(grant["access_token"], db) is None
    db.close()


# --- redirect handling ------------------------------------------------------------------

@pytest.mark.parametrize("evil", [
    "https://claude.ai/cb@evil.example",        # userinfo trick
    "https://claude.ai/cb/../../evil",          # traversal
    "https://claude.ai/cb#@evil.example",       # fragment
    "https://claude.ai/cb%2f%2eevil.example",   # encoded
    "http://claude.ai/cb",                      # scheme downgrade
    "https://CLAUDE.ai/cb",                     # case
])
def test_redirect_variants_that_are_not_the_registered_uri(client, raw_client, evil):
    """Every one of these is 'close to' the registered redirect. None of them is it."""
    cid = _register(raw_client)
    _, challenge = _pkce()
    r = client.post("/api/oauth/consent",
                    json={"client_id": cid, "redirect_uri": evil, "code_challenge": challenge})
    assert r.status_code == 400, f"{evil} was accepted"


# --- code handling ----------------------------------------------------------------------

def test_a_code_cannot_be_redeemed_by_a_different_client(client, raw_client):
    """The classic swap: register two clients, approve for one, redeem with the other."""
    good = _register(raw_client)
    evil = _register(raw_client)
    verifier, challenge = _pkce()
    consent = client.post("/api/oauth/consent",
                          json={"client_id": good, "redirect_uri": REDIRECT,
                                "code_challenge": challenge})
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]

    r = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": evil, "code_verifier": verifier})
    assert r.status_code >= 400


def test_a_code_cannot_be_spent_twice_over_http(client, raw_client):
    good = _register(raw_client)
    verifier, challenge = _pkce()
    consent = client.post("/api/oauth/consent",
                          json={"client_id": good, "redirect_uri": REDIRECT,
                                "code_challenge": challenge})
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]
    args = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": good, "code_verifier": verifier}
    assert raw_client.post("/token", data=args).status_code == 200
    assert raw_client.post("/token", data=args).status_code >= 400


# --- role -------------------------------------------------------------------------------

def test_an_oauth_token_does_not_escape_require_admin(client, raw_client, db_factory):
    """Same rule as a console key: the token acts as its user and cannot outrank them."""
    from fastapi import HTTPException
    from app.mcp_remote import _CALLER, _OAUTH_USER, _read
    from app import main

    _grant(client, raw_client)
    db = db_factory()
    row = db.query(Row).filter(Row.kind == "access").one()
    uid = row.user_id
    db.get(User, uid).role = "analyst"
    db.commit(); db.close()

    reset, creset = _OAUTH_USER.set(uid), _CALLER.set(None)
    try:
        assert _read(main.list_findings, admin=False, limit=1) is not None
        with pytest.raises(HTTPException) as e:
            _read(main.usage, admin=True)
        assert e.value.status_code == 403
    finally:
        _OAUTH_USER.reset(reset)
        _CALLER.reset(creset)


# --- registration: the scheme is not cosmetic -------------------------------------------
# Found by probing rather than by the tests above, which all assumed a registered redirect
# was at least a URL you could safely navigate to. Registration accepted javascript:, data:
# and file:, and consent matches the REGISTERED value exactly — so an approved grant would
# have handed the browser back a javascript: URL and executed it in the console's own
# origin, where the session token lives. That is account takeover, reachable by anyone who
# can register a client and get one admin to click Allow.

@pytest.mark.parametrize("uri", [
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "http://evil.example/cb",          # plain http off-loopback: the code crosses in clear
])
def test_registration_refuses_redirects_that_are_not_safe_to_navigate_to(raw_client, uri):
    r = raw_client.post("/register", json={"redirect_uris": [uri], "client_name": "probe"})
    assert r.status_code == 400, f"{uri} was accepted"
    assert r.json()["error"] == "invalid_redirect_uri"


@pytest.mark.parametrize("uri", ["https://claude.ai/cb", "http://localhost:8765/cb",
                                 "http://127.0.0.1:9000/callback"])
def test_registration_still_allows_what_real_clients_need(raw_client, uri):
    """https anywhere, and http on loopback — a local MCP client listens on 127.0.0.1 and
    cannot present a certificate for it, so refusing that would break the common case."""
    r = raw_client.post("/register", json={"redirect_uris": [uri], "client_name": "probe"})
    assert r.status_code in (200, 201), r.text


def test_consent_refuses_a_dangerous_redirect_even_if_it_was_stored(client, db_factory):
    """Defence in depth: a row written before the registration check existed must not turn
    into a navigation just because it matches itself."""
    db = db_factory()
    db.add(OAuthClient(client_id="legacy", client_name="Legacy",
                       redirect_uris="javascript:alert(1)", scope=READ_SCOPE))
    db.commit(); db.close()
    r = client.post("/api/oauth/consent",
                    json={"client_id": "legacy", "redirect_uri": "javascript:alert(1)",
                          "code_challenge": "chal"})
    assert r.status_code == 400


# --- discovery must never name someone else's deployment --------------------------------

def test_oauth_is_disabled_when_the_deployment_has_no_name():
    """A self-hosted install that never set PALIVANE_PUBLIC_URL must not publish
    app.palivane.io as its issuer: an MCP client doing discovery against THEIR server would
    be told to authorize against OURS, and their users would land on our login screen.

    Hermetic: wire into a throwaway app with a throwaway config, so this never depends on —
    or is polluted by — the live `settings`/`app` singletons (which made it order-flaky)."""
    from types import SimpleNamespace

    from fastapi import FastAPI
    from app import main as main_mod

    probe = FastAPI()
    cfg = SimpleNamespace(public_base_url="", database_url="postgresql://host/db")  # prod-shaped
    main_mod._wire_oauth(probe, cfg)

    paths = {getattr(r, "path", "") for r in probe.router.routes}
    assert not any(p.startswith("/.well-known/oauth") for p in paths), paths
    assert "/token" not in paths and "/authorize" not in paths


def test_oauth_is_wired_when_the_deployment_names_itself():
    from types import SimpleNamespace

    from fastapi import FastAPI
    from app import main as main_mod

    probe = FastAPI()
    cfg = SimpleNamespace(public_base_url="https://palivane.acme.example",
                          database_url="postgresql://host/db")
    main_mod._wire_oauth(probe, cfg)

    paths = {getattr(r, "path", "") for r in probe.router.routes}
    assert "/token" in paths and "/authorize" in paths
    assert any(p.startswith("/.well-known/oauth") for p in paths)
