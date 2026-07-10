"""MFA (TOTP + recovery codes): enrollment, login challenge, verify, disable."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app import totp
from app.main import app


def _code(secret: str) -> str:
    return totp._hotp(secret, int(time.time() // 30))


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

    vr = raw.post("/api/auth/mfa/verify", json={"challenge": challenge, "code": _code(secret)})
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
    r = client.post("/api/auth/mfa/disable", json={"code": _code(secret)})
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    assert client.get("/api/auth/me").json()["user"]["mfa_enabled"] is False
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
    code = _code(secret)
    ch = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch, "code": code}).status_code == 200
    # Same code (same time-step) presented again -> replay, rejected.
    ch2 = raw.post("/api/auth/login", json={"email": "admin@acme.com", "password": "password123"}).json()["challenge"]
    assert raw.post("/api/auth/mfa/verify", json={"challenge": ch2, "code": code}).status_code == 401
