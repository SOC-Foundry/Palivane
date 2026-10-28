"""SSO required: the org's IdP is the only way in for non-admins.

Without it, someone removed at the IdP (in an org that doesn't run SCIM) still has a password,
or can get one through /auth/forgot, or walks in through Google. Admins keep their password as
break-glass, and the setting lapses while no SSO is enabled, so it can't lock an org out.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

import app.email as email_mod
import app.oidc as oidc_mod
from app.config import settings
from app.main import app
from app.security import create_token

ANALYST = ("analyst@acme.com", "password123")


def _analyst(client):
    r = client.post("/api/users", json={"email": ANALYST[0], "password": ANALYST[1],
                                        "role": "analyst"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _enable_oidc(client, enabled=True):
    r = client.put("/api/oidc", json={"issuer": "https://idp.example", "client_id": "cid",
                                      "client_secret": "s", "enabled": enabled})
    assert r.status_code == 200, r.text


def _require(client, on=True):
    return client.patch("/api/tenant", json={"sso_required": on})


def _login(email, pw):
    return TestClient(app).post("/api/auth/login", json={"email": email, "password": pw})


@pytest.fixture
def sso_only(client):
    _analyst(client)
    _enable_oidc(client)
    r = _require(client)
    assert r.status_code == 200 and r.json()["sso_required"] is True
    return client


def test_analyst_password_login_is_refused(sso_only):
    r = _login(*ANALYST)
    assert r.status_code == 403 and "signs in with SSO" in r.json()["detail"]


def test_wrong_password_still_reads_as_wrong_password(sso_only):
    # Only someone holding the password learns that the org is SSO-only.
    assert _login(ANALYST[0], "not-it-123").status_code == 401


def test_admin_keeps_password_as_break_glass(sso_only):
    assert _login("admin@acme.com", "password123").status_code == 200


def test_requiring_sso_needs_sso_switched_on(client):
    _analyst(client)
    r = _require(client)
    assert r.status_code == 400 and "OIDC or SAML" in r.json()["detail"]
    _enable_oidc(client, enabled=False)
    assert _require(client).status_code == 400


def test_disabling_sso_lifts_the_requirement(sso_only):
    # The setting stays recorded, but with no IdP to sign in through it must not lock anyone out.
    _enable_oidc(sso_only, enabled=False)
    assert _login(*ANALYST).status_code == 200
    _enable_oidc(sso_only, enabled=True)
    assert _login(*ANALYST).status_code == 403


def test_turning_it_off_restores_password_login(sso_only):
    assert _require(sso_only, on=False).json()["sso_required"] is False
    assert _login(*ANALYST).status_code == 200


def test_forgot_sends_nothing_to_sso_only_users(sso_only, monkeypatch):
    sent = []
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "send", lambda to, subject, body: sent.append(to))
    r = TestClient(app).post("/api/auth/forgot", json={"email": ANALYST[0]})
    assert r.status_code == 200 and r.json() == {"ok": True}    # same answer as ever
    assert sent == []
    TestClient(app).post("/api/auth/forgot", json={"email": "admin@acme.com"})
    assert sent == ["admin@acme.com"]


def test_old_reset_link_cannot_set_a_password(sso_only, db_factory):
    from app.models import User
    db = db_factory()
    u = db.query(User).filter(User.email == ANALYST[0]).one()
    token = create_token({"typ": "pwreset", "sub": str(u.id), "tv": u.token_version}, ttl=600)
    db.close()
    r = TestClient(app).post("/api/auth/reset", json={"token": token, "password": "brand-new-pw-1"})
    assert r.status_code == 403
    assert _login(ANALYST[0], "brand-new-pw-1").status_code == 401


def test_invite_points_at_sso_not_a_password_link(client, monkeypatch):
    _enable_oidc(client)
    assert _require(client).status_code == 200
    sent = []
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "send", lambda to, subject, body: sent.append(body))
    r = client.post("/api/users", json={"email": "new@acme.com", "role": "analyst"})
    assert r.status_code == 200 and r.json()["invited"] is True
    assert "Sign in with SSO" in sent[0] and "#reset=" not in sent[0]


def test_google_sign_in_is_refused_for_sso_only_users(sso_only, monkeypatch):
    monkeypatch.setattr(settings, "google_oauth_client_id", "gid")
    monkeypatch.setattr(settings, "google_oauth_client_secret", "gsecret")
    monkeypatch.setattr(oidc_mod, "discover", lambda issuer: {
        "authorization_endpoint": "https://accounts.example/auth"})
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **k: {"id_token": "x"})
    monkeypatch.setattr(oidc_mod, "validate_id_token", lambda *a, **k: {
        "email": ANALYST[0], "email_verified": True})
    browser = TestClient(app)
    start = browser.get("/api/auth/google/login", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    r = browser.get("/api/auth/google/callback", params={"code": "c", "state": state},
                    follow_redirects=False)
    assert r.status_code == 403 and "signs in with SSO" in r.json()["detail"]
