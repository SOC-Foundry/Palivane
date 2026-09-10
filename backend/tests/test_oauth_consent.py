"""The consent step: the only place that decides whose data an OAuth token may read.

Every parameter here made a round trip through a URL in a browser, so each test is a way
someone could try to bend that round trip.
"""

from __future__ import annotations

from app.models import OAuthClient, OAuthCode, User
from app.oauth_provider import READ_SCOPE


def _client(db_factory, cid="c1", uris="https://claude.ai/cb", name="Claude"):
    db = db_factory()
    db.add(OAuthClient(client_id=cid, client_name=name, redirect_uris=uris, scope=READ_SCOPE))
    db.commit(); db.close()


def _consent(client, **over):
    body = {"client_id": "c1", "redirect_uri": "https://claude.ai/cb",
            "code_challenge": "chal", "state": "st"}
    body.update(over)
    return client.post("/api/oauth/consent", json=body)


def test_consent_requires_a_session(raw_client, db_factory):
    """Anonymous approval would let anyone mint a code for somebody else's account."""
    _client(db_factory)
    assert raw_client.post("/api/oauth/consent",
                           json={"client_id": "c1", "redirect_uri": "https://claude.ai/cb",
                                 "code_challenge": "chal"}).status_code in (401, 403)


def test_approval_binds_the_code_to_the_signed_in_user(client, db_factory):
    _client(db_factory)
    r = _consent(client)
    assert r.status_code == 200
    assert r.json()["redirect_to"].startswith("https://claude.ai/cb?")

    db = db_factory()
    row = db.query(OAuthCode).one()
    me = db.query(User).filter(User.email == "admin@acme.com").one()
    assert row.user_id == me.id              # identity from the session, not the body
    assert row.tenant_id == me.tenant_id
    assert row.scopes == READ_SCOPE
    assert row.used_at is None
    db.close()


def test_unregistered_redirect_is_refused(client, db_factory):
    """The check that stops an approved code being delivered to an attacker's callback."""
    _client(db_factory)
    r = _consent(client, redirect_uri="https://evil.example/cb")
    assert r.status_code == 400
    assert "redirect_uri" in r.text


def test_redirect_is_matched_exactly_not_by_prefix(client, db_factory):
    """https://claude.ai/cb.evil.example starts with the registered value. It is not it."""
    _client(db_factory)
    for bad in ("https://claude.ai/cb.evil.example", "https://claude.ai/cb/../x",
                "https://claude.ai/cbX", "https://claude.ai/cb?next=https://evil.example"):
        assert _consent(client, redirect_uri=bad).status_code == 400, bad


def test_missing_pkce_challenge_is_refused(client, db_factory):
    """Without a challenge the code is bearer-only: leaking it once is enough."""
    _client(db_factory)
    assert _consent(client, code_challenge="").status_code == 400


def test_unknown_client_is_refused(client, db_factory):
    _client(db_factory)
    assert _consent(client, client_id="not-registered").status_code == 404


def test_pending_reports_the_registered_name_not_the_url(client, db_factory):
    """The consent screen must not echo the caller's own claim about who it is."""
    _client(db_factory, name="Claude")
    r = client.get("/api/oauth/pending?client_id=c1&redirect_uri=https://claude.ai/cb")
    assert r.status_code == 200
    body = r.json()
    assert body["client_name"] == "Claude"          # from registration, not the query string
    assert body["scope"] == READ_SCOPE
    assert body["granting_as"]["email"] == "admin@acme.com"


def test_pending_refuses_an_unregistered_redirect(client, db_factory):
    """If the redirect is wrong there is nothing safe to render: approving would send the
    code somewhere unregistered, so the screen must not be shown at all."""
    _client(db_factory)
    assert client.get("/api/oauth/pending?client_id=c1"
                      "&redirect_uri=https://evil.example/cb").status_code == 400
