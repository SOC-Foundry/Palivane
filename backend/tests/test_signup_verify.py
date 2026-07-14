"""New-org signup email verification: gated on the email plane, blocks login until the
mailbox is confirmed, and falls back to immediate activation when email is off."""

from __future__ import annotations

import re

import app.email as email_mod


def _enable_email(monkeypatch):
    sent = []
    monkeypatch.setattr(email_mod.settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(email_mod.settings, "mail_from", "warden@test")
    monkeypatch.setattr(email_mod, "send", lambda to, subj, body: sent.append((to, subj, body)))
    return sent


def test_signup_no_email_plane_is_immediate(raw_client):
    # email disabled -> today's behavior: instant session, no verification.
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "NoMail Co", "email": "a@nomail-co.example", "password": "password123"})
    assert r.status_code == 200 and "access_token" in r.json()


def test_signup_requires_verification_when_email_on(raw_client, monkeypatch):
    sent = _enable_email(monkeypatch)
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Verify Co", "email": "founder@verify-co.example", "password": "password123"})
    assert r.status_code == 200
    assert r.json() == {"status": "verify_email", "org": "Verify Co"}
    assert "access_token" not in r.json()          # no session yet
    assert len(sent) == 1 and "verify" in sent[0][1].lower()

    # login is blocked until verified
    bad = raw_client.post("/api/auth/login", json={
        "email": "founder@verify-co.example", "password": "password123"})
    assert bad.status_code == 403 and "verify" in bad.json()["detail"].lower()

    # click the verify link
    token = re.search(r"token=([\w.\-]+)", sent[0][2]).group(1)
    v = raw_client.get(f"/api/auth/verify?token={token}", follow_redirects=False)
    assert v.status_code in (302, 307) and "#verified=ok" in v.headers["location"]

    # now login works
    ok = raw_client.post("/api/auth/login", json={
        "email": "founder@verify-co.example", "password": "password123"})
    assert ok.status_code == 200 and "access_token" in ok.json()


def test_bad_verify_token_bounces(raw_client, monkeypatch):
    _enable_email(monkeypatch)
    r = raw_client.get("/api/auth/verify?token=garbage", follow_redirects=False)
    assert "#verified=bad" in r.headers["location"]


def test_existing_users_unaffected(client):
    # The seeded admin (created pre-flag / via CLI) stays verified and can use the API.
    assert client.get("/api/auth/me").status_code == 200
