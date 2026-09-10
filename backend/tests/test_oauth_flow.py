"""End to end: dynamic registration → consent → PKCE code exchange → MCP with the token.

The point is the last step. Everything before it is protocol; the thing worth proving is
that a token obtained this way reaches the MCP endpoint AS THE APPROVING USER and no further.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from app.oauth_provider import READ_SCOPE

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}}
MCP_HDRS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
REDIRECT = "https://claude.ai/cb"


def _pkce():
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _register(raw_client):
    r = raw_client.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "Claude"})
    assert r.status_code in (200, 201), r.text
    return r.json()["client_id"]


def test_discovery_documents_point_clients_at_us(raw_client):
    a = raw_client.get("/.well-known/oauth-authorization-server")
    assert a.status_code == 200 and a.json()["token_endpoint"].endswith("/token")
    p = raw_client.get("/.well-known/oauth-protected-resource/api/mcp")
    assert p.status_code == 200
    assert p.json()["scopes_supported"] == [READ_SCOPE]


def test_full_grant_reaches_mcp_as_the_approving_user(client, raw_client, db_factory):
    from app.models import OAuthToken as Row, User

    client_id = _register(raw_client)
    verifier, challenge = _pkce()

    # The user approves in the console, with their session — never anonymously.
    consent = client.post("/api/oauth/consent",
                          json={"client_id": client_id, "redirect_uri": REDIRECT,
                                "code_challenge": challenge, "state": "xyz"})
    assert consent.status_code == 200, consent.text
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]

    tok = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": client_id, "code_verifier": verifier})
    assert tok.status_code == 200, tok.text
    access = tok.json()["access_token"]

    # The token belongs to the user who approved, not to the client that asked.
    db = db_factory()
    row = db.query(Row).filter(Row.kind == "access").one()
    admin = db.query(User).filter(User.email == "admin@acme.com").one()
    assert row.user_id == admin.id and row.tenant_id == admin.tenant_id
    admin_id = admin.id
    db.close()

    # Resolved at the layer that decides identity, not through the transport: the MCP
    # session manager is single-use per process, so a test that stands one up cannot share a
    # worker with another that does. The transport itself is covered in test_mcp_remote.
    from app.mcp_remote import _oauth_user_id
    db = db_factory()
    assert _oauth_user_id(access, db) == admin_id
    db.close()


def test_a_wrong_pkce_verifier_is_refused(client, raw_client):
    """Without this the code is bearer-only and interception is enough."""
    client_id = _register(raw_client)
    _, challenge = _pkce()
    consent = client.post("/api/oauth/consent",
                          json={"client_id": client_id, "redirect_uri": REDIRECT,
                                "code_challenge": challenge})
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]

    bad = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": client_id, "code_verifier": "w" * 64})
    assert bad.status_code >= 400


def test_revoked_access_token_stops_reaching_mcp(client, raw_client, db_factory):
    from app.models import OAuthToken as Row
    from app.oauth_provider import _now

    client_id = _register(raw_client)
    verifier, challenge = _pkce()
    consent = client.post("/api/oauth/consent",
                          json={"client_id": client_id, "redirect_uri": REDIRECT,
                                "code_challenge": challenge})
    code = consent.json()["redirect_to"].split("code=")[1].split("&")[0]
    access = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": client_id, "code_verifier": verifier}).json()["access_token"]

    db = db_factory()
    db.query(Row).filter(Row.kind == "access").one().revoked_at = _now()
    db.commit(); db.close()

    # The wrapper refuses before the transport is involved, so this needs no lifespan.
    r = raw_client.post("/api/mcp/", json=INIT,
                        headers={**MCP_HDRS, "Authorization": f"Bearer {access}"})
    assert r.status_code == 401
