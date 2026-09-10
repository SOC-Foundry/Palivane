"""OAuth token mechanics for the remote MCP endpoint.

Nothing is wired to routes yet. These exist so the parts that decide who can read what are
argued with BEFORE a browser can reach them — every test below is a property that, if it
stopped holding, would be a way to read another tenant's findings.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from mcp.shared.auth import OAuthClientInformationFull

from app.models import OAuthCode, OAuthToken as OAuthTokenRow, Tenant, User
from app.oauth_provider import READ_SCOPE, PalivaneOAuthProvider, _now
from app.security import hash_token


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def provider(db_factory):
    Session = db_factory

    def factory():
        db = Session()
        return db, db.close

    return PalivaneOAuthProvider(factory), Session


def _client(cid="c1"):
    return OAuthClientInformationFull(
        client_id=cid, redirect_uris=["https://claude.ai/cb"],
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        token_endpoint_auth_method="none")


def _register(p, cid="c1", uris=("https://claude.ai/cb",), scope=None):
    info = OAuthClientInformationFull(
        client_id=cid, redirect_uris=list(uris), scope=scope,
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        token_endpoint_auth_method="none")
    _run(p.register_client(info))


def _seed_user(Session):
    db = Session()
    t = Tenant(name="Acme", slug="acme-oauth")
    db.add(t); db.commit(); db.refresh(t)
    u = User(email="o@acme.com", password_hash="x", role="admin", tenant_id=t.id, active=True)
    db.add(u); db.commit(); db.refresh(u)
    uid, tid = u.id, t.id
    db.close()
    return uid, tid


def _mint_code(Session, code, client_id, uid, tid, ttl=timedelta(seconds=60), used=None):
    db = Session()
    db.add(OAuthCode(code_hash=hash_token(code), client_id=client_id, user_id=uid,
                     tenant_id=tid, redirect_uri="https://claude.ai/cb",
                     code_challenge="abc", scopes=READ_SCOPE,
                     expires_at=_now() + ttl, used_at=used))
    db.commit(); db.close()


# --- registration -------------------------------------------------------------------

def test_registration_requires_a_redirect_uri(provider):
    p, _ = provider
    with pytest.raises(ValueError):
        _register(p, uris=())


def test_registration_cannot_widen_its_own_scope(provider):
    """A client asking for more than read must not receive it: registration is open, so
    whatever it requests is attacker-controlled input."""
    p, _ = provider
    _register(p, scope="palivane:read palivane:write admin")
    got = _run(p.get_client("c1"))
    assert got.scope == READ_SCOPE


# --- authorization codes ------------------------------------------------------------

def test_code_is_single_use(provider):
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-1", "c1", uid, tid)

    loaded = _run(p.load_authorization_code(_client(), "code-1"))
    assert loaded is not None
    _run(p.exchange_authorization_code(_client(), loaded))

    # Replay must fail: a code lifted from a log or a Referer header is worth nothing.
    assert _run(p.load_authorization_code(_client(), "code-1")) is None
    with pytest.raises(ValueError):
        _run(p.exchange_authorization_code(_client(), loaded))


def test_expired_code_is_refused(provider):
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-old", "c1", uid, tid, ttl=timedelta(seconds=-1))
    assert _run(p.load_authorization_code(_client(), "code-old")) is None


def test_code_belonging_to_another_client_is_refused(provider):
    """The classic swap: a code issued to one client, presented by another."""
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p, "c1")
    _register(p, "c2")
    _mint_code(Session, "code-2", "c1", uid, tid)
    assert _run(p.load_authorization_code(_client("c2"), "code-2")) is None


def test_code_carries_the_approving_user(provider):
    """subject IS the consent binding — without it a token belongs to nobody in particular."""
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-3", "c1", uid, tid)
    loaded = _run(p.load_authorization_code(_client(), "code-3"))
    assert loaded.subject == str(uid)


# --- tokens ---------------------------------------------------------------------------

def test_tokens_are_never_stored_in_the_clear(provider):
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-4", "c1", uid, tid)
    loaded = _run(p.load_authorization_code(_client(), "code-4"))
    tok = _run(p.exchange_authorization_code(_client(), loaded))

    db = Session()
    stored = {r.token_hash for r in db.query(OAuthTokenRow).all()}
    db.close()
    assert tok.access_token not in stored and tok.refresh_token not in stored
    assert hash_token(tok.access_token) in stored


def test_refresh_rotates_and_kills_the_old_token(provider):
    """A stolen refresh token must stop working the moment the real holder uses theirs."""
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-5", "c1", uid, tid)
    loaded = _run(p.load_authorization_code(_client(), "code-5"))
    first = _run(p.exchange_authorization_code(_client(), loaded))

    rt = _run(p.load_refresh_token(_client(), first.refresh_token))
    second = _run(p.exchange_refresh_token(_client(), rt, [READ_SCOPE]))

    assert second.refresh_token != first.refresh_token
    assert _run(p.load_refresh_token(_client(), first.refresh_token)) is None
    assert _run(p.load_access_token(second.access_token)) is not None


def test_refresh_cannot_widen_scope(provider):
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-6", "c1", uid, tid)
    loaded = _run(p.load_authorization_code(_client(), "code-6"))
    first = _run(p.exchange_authorization_code(_client(), loaded))
    rt = _run(p.load_refresh_token(_client(), first.refresh_token))

    widened = _run(p.exchange_refresh_token(_client(), rt, ["palivane:write", "admin"]))
    assert widened.scope == READ_SCOPE


def test_revoked_and_expired_access_tokens_stop_loading(provider):
    p, Session = provider
    uid, tid = _seed_user(Session)
    _register(p)
    _mint_code(Session, "code-7", "c1", uid, tid)
    loaded = _run(p.load_authorization_code(_client(), "code-7"))
    tok = _run(p.exchange_authorization_code(_client(), loaded))

    at = _run(p.load_access_token(tok.access_token))
    assert at is not None and at.subject == str(uid)

    _run(p.revoke_token(at))
    assert _run(p.load_access_token(tok.access_token)) is None


def test_unknown_client_and_token_are_simply_absent(provider):
    p, _ = provider
    assert _run(p.get_client("nope")) is None
    assert _run(p.load_access_token("pat_nothing")) is None
