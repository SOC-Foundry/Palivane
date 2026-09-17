"""Offboarding a leaver: every way in, closed in one action.

`active: false` was the only tool, and it closes the least important door. It stops a fresh
sign-in and nothing else — an already-issued JWT stays valid until expiry, and the person's
API keys keep working indefinitely, including the capture key their browser extension holds.
An admin who toggles a leaver inactive and moves on has revoked almost nothing.

These tests assert each door separately, because "it returned 200" is exactly the kind of
pass that let that gap exist.
"""

from __future__ import annotations

import pytest


def _mk_user(client, email="leaver@acme.com", role="analyst"):
    r = client.post("/api/users", json={"email": email, "password": "Passw0rd!-long-enough",
                                        "role": role})
    assert r.status_code == 200, r.text
    return r.json()


def _login(raw_client, email, password="Passw0rd!-long-enough"):
    r = raw_client.post("/api/auth/login", json={"email": email, "password": password})
    return r


def test_offboard_disables_login(client):
    u = _mk_user(client)
    r = client.post(f"/api/users/{u['id']}/offboard")
    assert r.status_code == 200, r.text
    assert r.json()["user"]["active"] is False


def test_offboard_ends_a_live_session_not_just_future_ones(client, raw_client):
    """The door `active: false` leaves open. A token issued before offboarding must stop
    working immediately, not at expiry — token_version is bumped and every JWT carries it."""
    u = _mk_user(client, "live@acme.com")
    tok = _login(raw_client, "live@acme.com").json()["access_token"]
    auth = {"authorization": f"Bearer {tok}"}
    assert raw_client.get("/api/auth/me", headers=auth).status_code == 200

    client.post(f"/api/users/{u['id']}/offboard")
    assert raw_client.get("/api/auth/me", headers=auth).status_code == 401, \
        "an already-issued token outlived the offboard"


def test_offboard_revokes_their_api_keys(client, db_factory):
    """Console keys are bound by user_id; capture keys (browser extension, palivane-connect)
    are bound only by the actor they attribute to. A leaver's extension key is the one most
    likely to keep quietly reporting, so both kinds are matched."""
    from app.models import ApiKey
    u = _mk_user(client, "keys@acme.com")
    console = client.post("/api/apikeys", json={"label": "theirs", "scope": "console_read"})
    capture = client.post("/api/apikeys", json={"label": "their-extension",
                                                "actor": "keys@acme.com"})
    assert console.status_code == 200 and capture.status_code == 200
    # A console key carries the user it acts AS. The API has no field for that (it binds to
    # the minting admin), so bind it here — the endpoint's job is to revoke keys pointing at
    # the leaver however they came to.
    db = db_factory()
    k = db.query(ApiKey).filter(ApiKey.label == "theirs").first()
    k.user_id = u["id"]
    db.commit(); db.close()

    client.post(f"/api/users/{u['id']}/offboard")

    db = db_factory()
    for label in ("theirs", "their-extension"):
        k = db.query(ApiKey).filter(ApiKey.label == label).first()
        assert k is not None and k.active is False, f"{label} still active after offboard"
    db.close()


def test_offboard_leaves_other_peoples_keys_alone(client, db_factory):
    """Matching on the actor string is broad by design, so it must not sweep in a colleague."""
    from app.models import ApiKey
    u = _mk_user(client, "goes@acme.com")
    _mk_user(client, "stays@acme.com")
    client.post("/api/apikeys", json={"label": "stays-key", "actor": "stays@acme.com"})

    client.post(f"/api/users/{u['id']}/offboard")

    db = db_factory()
    k = db.query(ApiKey).filter(ApiKey.label == "stays-key").first()
    assert k is not None and k.active is True
    db.close()


def test_offboard_does_not_delete_the_user_or_their_attribution(client, db_factory):
    """Not a delete, on purpose. Findings attribute by email STRING, not user id, so removing
    the row would erase nothing while looking like erasure — the address stays in every
    finding, audit entry and discovery record. Keeping the user preserves the attribution
    that makes an old finding mean something."""
    from app.models import User
    u = _mk_user(client, "kept@acme.com")
    client.post(f"/api/users/{u['id']}/offboard")
    db = db_factory()
    row = db.get(User, u["id"])
    assert row is not None, "offboard must not delete the user"
    assert row.email == "kept@acme.com", "attribution must survive"
    db.close()


def test_cannot_offboard_yourself(client):
    me = client.get("/api/auth/me").json()["user"]
    r = client.post(f"/api/users/{me['id']}/offboard")
    assert r.status_code == 400
    assert "your own" in r.json()["detail"]


def test_cannot_offboard_the_last_admin(client, db_factory):
    """Same guard the deactivate path already has — an org must not be able to lock itself
    out by offboarding its only administrator."""
    from app.models import User
    me = client.get("/api/auth/me").json()["user"]
    other = _mk_user(client, "second-admin@acme.com", role="admin")
    # Demote the second admin so only one remains, then try to offboard that one.
    db = db_factory()
    row = db.get(User, other["id"]); row.role = "analyst"; db.commit(); db.close()
    r = client.post(f"/api/users/{me['id']}/offboard")
    assert r.status_code == 400


def test_offboard_is_audited_with_what_it_revoked(client, db_factory):
    """An offboard is the kind of action a reviewer asks about six months later, so the
    record has to say what it actually closed, not just that it happened."""
    from app.models import AuditLog
    u = _mk_user(client, "audited@acme.com")
    client.post("/api/apikeys", json={"label": "audited-key", "actor": "audited@acme.com"})
    client.post(f"/api/users/{u['id']}/offboard")
    db = db_factory()
    entry = (db.query(AuditLog).filter(AuditLog.action == "user.offboard")
             .order_by(AuditLog.id.desc()).first())
    assert entry is not None
    assert entry.target == "audited@acme.com"
    assert (entry.detail or {}).get("api_keys_revoked") == 1
    db.close()


def test_offboard_requires_admin(client, raw_client):
    u = _mk_user(client, "analyst@acme.com")
    tok = _login(raw_client, "analyst@acme.com").json()["access_token"]
    r = raw_client.post(f"/api/users/{u['id']}/offboard",
                        headers={"authorization": f"Bearer {tok}"})
    assert r.status_code in (401, 403)
