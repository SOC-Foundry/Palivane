"""MFA (TOTP + recovery codes): enrollment, login challenge, verify, disable."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app import totp
from app.main import app


def _code(secret: str, ahead: int = 0) -> str:
    """The code for the current time-step, or `ahead` steps later. Each step's code is
    single-use (enrolment's confirm included), and verify accepts one step either side of
    now, so the use after enrolment takes ahead=1."""
    return totp._hotp(secret, int(time.time() // 30) + ahead)


def _enroll(client) -> tuple[str, list[str]]:
    secret = client.post("/api/auth/mfa/setup").json()["secret"]
    codes = client.post("/api/auth/mfa/confirm", json={"code": _code(secret)}).json()["recovery_codes"]
    return secret, codes


def test_setup_confirm_and_me_reflects_enabled(client):
    s = client.post("/api/auth/mfa/setup").json()
    assert s["otpauth_uri"].startswith("otpauth://totp/")
    r = client.post("/api/auth/mfa/confirm", json={"code": _code(s["secret"])})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10
    assert client.get("/api/auth/me").json()["user"]["mfa_enabled"] is True


def test_confirm_requires_setup_and_valid_code(client):
    assert client.post("/api/auth/mfa/confirm", json={"code": "123456"}).status_code == 400
    secret = client.post("/api/auth/mfa/setup").json()["secret"]
    assert client.post("/api/auth/mfa/confirm", json={"code": "000001"}).status_code == 400 or \
        _code(secret) == "000001"


def test_login_requires_second_factor_then_totp(client):
    secret, _ = _enroll(client)
    raw = TestClient(app)
    lr = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"})
    assert lr.status_code == 200 and lr.json().get("mfa_required") is True
    assert "access_token" not in lr.json()
    challenge = lr.json()["challenge"]

    vr = raw.post("/api/auth/mfa/verify", json={"challenge": challenge, "code": _code(secret, 1)})
    assert vr.status_code == 200 and "access_token" in vr.json()
    token = vr.json()["access_token"]
    assert raw.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_recovery_code_works_once(client):
    _, codes = _enroll(client)
    raw = TestClient(app)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": codes[0]}).status_code == 200
    # reusing the same recovery code fails
    ch2 = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch2, "code": codes[0]}).status_code == 401


def test_bad_code_rejected(client):
    secret, _ = _enroll(client)
    raw = TestClient(app)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    wrong = "999999" if _code(secret) != "999999" else "111111"
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": wrong}).status_code == 401


def test_disable_returns_to_password_only(client):
    secret, _ = _enroll(client)
    r = client.post("/api/auth/mfa/disable", json={"code": _code(secret, 1)})
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    # Disabling ends every session; this one carries on with the token it was handed.
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert me.json()["user"]["mfa_enabled"] is False
    raw = TestClient(app)
    lr = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"})
    assert "access_token" in lr.json() and not lr.json().get("mfa_required")

def test_mfa_challenge_is_not_a_session_token(client):
    # The post-password MFA challenge must NOT authenticate protected routes — otherwise a
    # caller who only passed the first factor could skip MFA by using the challenge directly.
    _enroll(client)
    raw = TestClient(app)
    challenge = raw.post("/api/auth/login",
                         json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    r = raw.get("/api/auth/me", headers={"Authorization": f"Bearer {challenge}"})
    assert r.status_code == 401


def test_totp_code_cannot_be_replayed(client):
    secret, _ = _enroll(client)
    raw = TestClient(app)
    code = _code(secret, 1)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": code}).status_code == 200
    # Same code (same time-step) presented again -> replay, rejected.
    ch2 = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch2, "code": code}).status_code == 401


# --- step-up: changing a second factor needs a recent sign-in, not just a live session -----

def test_stale_session_cannot_set_up_or_disable_mfa(client, monkeypatch):
    # A stolen session could otherwise enrol its own authenticator (locking the owner out at
    # their next sign-in) or switch MFA off.
    secret, _ = _enroll(client)
    import app.auth as auth_mod
    monkeypatch.setattr(auth_mod, "_STEP_UP_SECONDS", -1)    # every session is now "old"
    r = client.post("/api/auth/mfa/disable", json={"code": _code(secret)})
    assert r.status_code == 403 and "sign back in" in r.json()["detail"]
    assert client.get("/api/auth/me").json()["user"]["mfa_enabled"] is True


def test_stale_session_cannot_start_enrolment(client, monkeypatch):
    import app.auth as auth_mod
    monkeypatch.setattr(auth_mod, "_STEP_UP_SECONDS", -1)
    assert client.post("/api/auth/mfa/setup").status_code == 403


def test_disable_code_cannot_be_guessed(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "login_max_fails", 2)
    secret, _ = _enroll(client)
    wrong = "999999" if _code(secret) != "999999" else "111111"
    for _ in range(2):
        assert client.post("/api/auth/mfa/disable", json={"code": wrong}).status_code == 400
    # Throttled now, even with the right code.
    assert client.post("/api/auth/mfa/disable", json={"code": _code(secret, 1)}).status_code == 429


def test_disable_ends_other_sessions(client):
    secret, recovery = _enroll(client)
    raw = TestClient(app)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com",
                                           "password": "password123"}).json()["challenge"]
    other = raw.post("/api/auth/mfa/verify",
                     json={"challenge": ch, "code": _code(secret, 1)}).json()["access_token"]
    r = client.post("/api/auth/mfa/disable", json={"code": recovery[0]})
    assert r.status_code == 200
    assert raw.get("/api/auth/me", headers={"Authorization": f"Bearer {other}"}).status_code == 401


# --- the guess limit, single-use codes, and what disabling ends ------------------------------

def test_password_logins_do_not_reset_the_mfa_guess_limit(client, monkeypatch):
    """Clearing the failure count at the password step gave anyone holding the password a
    fresh budget of TOTP guesses on every login (QA: 40 wrong guesses, no 429)."""
    from app.config import settings
    monkeypatch.setattr(settings, "login_max_fails", 5)
    secret, _ = _enroll(client)
    wrong = "999999" if _code(secret, 1) != "999999" and _code(secret) != "999999" else "111111"
    raw = TestClient(app)
    codes = []
    for _ in range(3):                      # three fresh logins, guessing each time
        lr = raw.post("/api/auth/login", json={"email": "admin@acme.com",
                                               "password": "password123"})
        if lr.status_code == 429:
            codes.append(429)
            break
        ch = lr.json()["challenge"]
        for _ in range(4):
            codes.append(raw.post("/api/auth/mfa/verify",
                                  json={"challenge": ch, "code": wrong}).status_code)
    assert 429 in codes and codes.index(429) <= 5   # throttled across logins, not per login


def test_the_code_that_confirmed_cannot_sign_in(client):
    secret = client.post("/api/auth/mfa/setup").json()["secret"]
    code = _code(secret)
    assert client.post("/api/auth/mfa/confirm", json={"code": code}).status_code == 200
    raw = TestClient(app)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com",
                                           "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": code}).status_code == 401


def test_confirm_cannot_reissue_recovery_codes_once_on(client):
    secret, first = _enroll(client)
    r = client.post("/api/auth/mfa/confirm", json={"code": _code(secret, 1)})
    assert r.status_code == 400 and "already enabled" in r.json()["detail"]
    raw = TestClient(app)                   # the original recovery codes still work
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com",
                                           "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": first[0]}).status_code == 200


def test_a_used_code_cannot_disable_mfa(client):
    secret, _ = _enroll(client)
    used = _code(secret, 1)
    raw = TestClient(app)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com",
                                           "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": used}).status_code == 200
    assert client.post("/api/auth/mfa/disable", json={"code": used}).status_code == 400
    assert client.get("/api/auth/me").json()["user"]["mfa_enabled"] is True


def test_disabling_mfa_revokes_oauth_grants(client, db_factory):
    from datetime import timedelta

    from app.models import OAuthToken, User
    from app.oauth_provider import _now
    secret, recovery = _enroll(client)
    db = db_factory()
    admin = db.query(User).filter(User.email == "admin@acme.com").one()
    db.add(OAuthToken(token_hash="h-mfa", kind="refresh", client_id="c1", user_id=admin.id,
                      tenant_id=admin.tenant_id, scopes="palivane:read",
                      expires_at=_now() + timedelta(days=1)))
    db.commit(); db.close()
    assert client.post("/api/auth/mfa/disable", json={"code": recovery[0]}).status_code == 200
    db = db_factory()
    assert db.query(OAuthToken).filter(OAuthToken.token_hash == "h-mfa").one().revoked_at
    db.close()
