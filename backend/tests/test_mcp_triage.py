"""Triage over the hosted MCP endpoint: the palivane:triage scope, end to end.

The remote MCP server was read-only, so "ask Claude to triage a finding" worked only through the
self-installed stdio server with a write key. Triage is now a separate OAuth scope: a client may
register for it, the person sees it as its own line on the consent screen and can untick it, the
token carries it, and set_finding_status runs only on a connection that holds it (or on a
console_write key). The console's own rules ride along: only an admin can dismiss.
"""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException

from app import mcp_remote
from app.oauth_provider import READ_SCOPE, TRIAGE_SCOPE

REDIRECT = "https://claude.ai/cb"
BOTH = f"{READ_SCOPE} {TRIAGE_SCOPE}"


def _pkce():
    verifier = "v" * 64
    return verifier, base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _register(raw_client, scope=None):
    body = {"redirect_uris": [REDIRECT], "client_name": "Claude"}
    if scope is not None:
        body["scope"] = scope
    r = raw_client.post("/register", json=body)
    assert r.status_code in (200, 201), r.text
    return r.json()["client_id"]


def _grant(client, raw_client, client_id, consent_scope):
    verifier, challenge = _pkce()
    consent = client.post("/api/oauth/consent", json={
        "client_id": client_id, "redirect_uri": REDIRECT, "code_challenge": challenge,
        "scope": consent_scope})
    assert consent.status_code == 200, consent.text
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]
    tok = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": client_id, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    return tok.json()


# --- the grant -------------------------------------------------------------------------------

def test_a_client_registered_for_triage_gets_it_when_the_person_allows(client, raw_client,
                                                                       db_factory):
    cid = _register(raw_client, BOTH)
    tok = _grant(client, raw_client, cid, BOTH)
    assert tok["scope"] == BOTH
    db = db_factory()
    _, scopes = mcp_remote._oauth_grant(tok["access_token"], db)
    db.close()
    assert mcp_remote.triage_allowed(oauth_scopes=scopes) is True


def test_the_person_can_untick_triage(client, raw_client):
    cid = _register(raw_client, BOTH)
    assert _grant(client, raw_client, cid, READ_SCOPE)["scope"] == READ_SCOPE


def test_consent_cannot_grant_what_registration_did_not(client, raw_client):
    # A read-only client: whatever the consent body says, the grant is read.
    cid = _register(raw_client)
    assert _grant(client, raw_client, cid, BOTH)["scope"] == READ_SCOPE


def test_registration_cannot_mint_an_unknown_scope(raw_client):
    r = raw_client.post("/register", json={"redirect_uris": [REDIRECT],
                                            "scope": "palivane:read palivane:admin"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"


def test_refresh_keeps_triage_and_cannot_add_it(client, raw_client):
    cid = _register(raw_client, BOTH)
    read_only = _grant(client, raw_client, cid, READ_SCOPE)
    r = raw_client.post("/token", data={"grant_type": "refresh_token", "client_id": cid,
                                        "refresh_token": read_only["refresh_token"],
                                        "scope": BOTH})
    assert r.status_code == 400 and r.json()["error"] == "invalid_scope"


# --- what the screens are told ---------------------------------------------------------------

def test_authorize_carries_the_requested_scope_to_consent(raw_client):
    cid = _register(raw_client, BOTH)
    _, challenge = _pkce()
    r = raw_client.get("/authorize", params={
        "response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s",
        "scope": BOTH}, follow_redirects=False)
    assert r.status_code in (302, 307), r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["scope"] == [BOTH]


def test_pending_offers_triage_only_within_registration(client, raw_client):
    both = _register(raw_client, BOTH)
    read = _register(raw_client)
    ask = lambda cid: client.get("/api/oauth/pending", params={
        "client_id": cid, "redirect_uri": REDIRECT, "scope": BOTH}).json()
    offered = ask(both)
    assert [s["scope"] for s in offered["scopes"]] == [READ_SCOPE, TRIAGE_SCOPE]
    assert [s["writes"] for s in offered["scopes"]] == [False, True]
    assert [s["scope"] for s in ask(read)["scopes"]] == [READ_SCOPE]   # URL can't add it


# --- the tool ----------------------------------------------------------------------------------

@pytest.fixture
def finding(client, db_factory):
    from app.models import Finding, User
    db = db_factory()
    admin = db.query(User).filter(User.email == "admin@acme.com").one()
    f = Finding(tenant_id=admin.tenant_id, severity="high", sender="dev@acme.com",
                status="open")
    db.add(f); db.commit()
    ids = {"finding": f.id, "admin": admin.id, "tenant": admin.tenant_id}
    db.close()
    return ids


def _as(user_id, can_triage):
    return mcp_remote._OAUTH_USER.set(user_id), mcp_remote._CAN_TRIAGE.set(can_triage)


def _reset(tokens):
    mcp_remote._OAUTH_USER.reset(tokens[0])
    mcp_remote._CAN_TRIAGE.reset(tokens[1])


def test_read_only_connection_cannot_triage(finding):
    t = _as(finding["admin"], False)
    try:
        with pytest.raises(HTTPException) as e:
            mcp_remote.set_finding_status(finding["finding"], "triaged")
        assert e.value.status_code == 403 and "read-only" in e.value.detail
    finally:
        _reset(t)


def test_triage_connection_changes_status_and_audits_it(finding, client, db_factory):
    t = _as(finding["admin"], True)
    try:
        assert mcp_remote.set_finding_status(finding["finding"], "triaged")["status"] == "triaged"
    finally:
        _reset(t)
    from app.models import AuditLog, Finding
    db = db_factory()
    assert db.get(Finding, finding["finding"]).reviewed_by == "admin@acme.com"
    entry = db.query(AuditLog).filter(AuditLog.action == "finding.status").one()
    assert entry.actor == "admin@acme.com" and entry.detail.get("via") == "mcp"
    db.close()


def test_an_analyst_still_cannot_dismiss(finding, db_factory):
    from app.models import User
    db = db_factory()
    analyst = User(tenant_id=finding["tenant"], email="an@acme.com", role="analyst",
                   password_hash="x", active=True)
    db.add(analyst); db.commit()
    aid = analyst.id
    db.close()
    t = _as(aid, True)
    try:
        assert mcp_remote.set_finding_status(finding["finding"], "triaged")["status"] == "triaged"
        with pytest.raises(HTTPException) as e:
            mcp_remote.set_finding_status(finding["finding"], "dismissed", "false_positive")
        assert e.value.status_code == 403 and "admin" in e.value.detail
    finally:
        _reset(t)


@pytest.mark.parametrize("scopes,key,allowed", [
    ([READ_SCOPE, TRIAGE_SCOPE], None, True),
    ([READ_SCOPE], None, False),
    ([], None, False),
    (None, "console_write", True),
    (None, "console_read", False),
    (None, "ingest", False),
])
def test_who_may_triage(scopes, key, allowed):
    assert mcp_remote.triage_allowed(oauth_scopes=scopes, key_scope=key) is allowed
