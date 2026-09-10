"""Seeing authorized apps, and cutting them off.

The consent screen used to promise this and it did not exist. These pin that it does now,
and that revoking actually ends access rather than looking like it did.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta

from app import users as users_cli
from app.models import OAuthToken as Row, User
from app.oauth_provider import _now, prune

REDIRECT = "https://claude.ai/cb"


def _pkce():
    v = "v" * 64
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def _grant(client, raw_client, name="Claude"):
    cid = raw_client.post("/register", json={"redirect_uris": [REDIRECT],
                                             "client_name": name}).json()["client_id"]
    verifier, challenge = _pkce()
    code = client.post("/api/oauth/consent",
                       json={"client_id": cid, "redirect_uri": REDIRECT,
                             "code_challenge": challenge}
                       ).json()["redirect_to"].split("code=")[1].split("&")[0]
    tok = raw_client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": cid, "code_verifier": verifier}).json()
    return cid, tok


def test_a_grant_shows_up_once_not_once_per_token(client, raw_client):
    """Access and refresh are two rows for one approval, and refresh rotation writes more.
    A raw token list would read as several grants for a single click."""
    cid, _ = _grant(client, raw_client)
    grants = client.get("/api/oauth/grants").json()["grants"]
    assert len([g for g in grants if g["client_id"] == cid]) == 1
    g = next(g for g in grants if g["client_id"] == cid)
    assert g["client_name"] == "Claude"
    assert g["granted_by"] == "admin@acme.com"


def test_revoking_ends_access_for_real(client, raw_client, db_factory):
    """Both token kinds, or it is theatre: a live refresh token mints a new access token
    within the hour and the app carries on."""
    from app.mcp_remote import _oauth_user_id

    cid, tok = _grant(client, raw_client)
    db = db_factory()
    assert _oauth_user_id(tok["access_token"], db) is not None
    db.close()

    r = client.delete(f"/api/oauth/grants/{cid}")
    assert r.status_code == 200 and r.json()["revoked"] >= 2   # access AND refresh

    db = db_factory()
    assert _oauth_user_id(tok["access_token"], db) is None
    assert db.query(Row).filter(Row.client_id == cid,
                                Row.revoked_at.is_(None)).count() == 0
    db.close()
    assert not [g for g in client.get("/api/oauth/grants").json()["grants"]
                if g["client_id"] == cid]


def test_revoking_something_that_is_not_granted_is_a_404(client):
    assert client.delete("/api/oauth/grants/never-registered").status_code == 404


def test_a_non_admin_sees_and_revokes_only_their_own(client, raw_client, db_factory):
    """An analyst must not be able to cut off an app somebody else approved, nor see it."""
    cid, _ = _grant(client, raw_client)          # approved by the admin

    db = db_factory()
    users_cli.create_user(db, "acme", "an@acme.com", "analystpass123", "analyst")
    db.close()
    from fastapi.testclient import TestClient
    from app.main import app
    an = TestClient(app)
    tokn = an.post("/api/auth/login", json={"email": "an@acme.com",
                                            "password": "analystpass123"}).json()["access_token"]
    an.headers.update({"Authorization": f"Bearer {tokn}"})

    assert an.get("/api/oauth/grants").json()["grants"] == []
    assert an.delete(f"/api/oauth/grants/{cid}").status_code == 404
    # And the admin's grant is untouched by the attempt.
    assert [g for g in client.get("/api/oauth/grants").json()["grants"] if g["client_id"] == cid]


def test_prune_clears_spent_codes_and_dead_tokens_but_not_live_ones(client, raw_client, db_factory):
    cid, tok = _grant(client, raw_client)
    db = db_factory()
    live_before = db.query(Row).filter(Row.revoked_at.is_(None)).count()

    # A token revoked long enough ago that nobody is still debugging it.
    old = db.query(Row).filter(Row.kind == "refresh").one()
    old.revoked_at = _now() - timedelta(days=30)
    db.commit()
    old_id = old.id            # read before prune: afterwards the instance is gone and
                               # touching it raises rather than returning the id

    prune(db)

    assert db.query(Row).filter(Row.id == old_id).count() == 0
    assert db.query(Row).filter(Row.revoked_at.is_(None)).count() == live_before - 1
    from app.models import OAuthCode
    assert db.query(OAuthCode).count() == 0      # the code was spent at exchange
    db.close()
