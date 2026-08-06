"""Email plane: password reset, join-request mailbox verification, email invites.
All flows must degrade to email-less behavior when SMTP is unconfigured."""

from __future__ import annotations

import re

import app.email as email_mod


def _enable_email(monkeypatch):
    """Turn the plane 'on' and capture sends instead of touching SMTP."""
    sent = []
    monkeypatch.setattr(email_mod.settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(email_mod.settings, "mail_from", "warden@test")
    monkeypatch.setattr(email_mod, "send",
                        lambda to, subject, body: sent.append((to, subject, body)))
    return sent


def _token(body: str, kind: str) -> str:
    m = re.search(r"#reset=([\w.\-]+)" if kind == "reset" else r"token=([\w.\-]+)", body)
    assert m, body
    return m.group(1)


def test_health_reports_email_enabled(raw_client, monkeypatch):
    assert raw_client.get("/api/health").json()["email_enabled"] is False
    monkeypatch.setattr(email_mod.settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(email_mod.settings, "mail_from", "warden@test")
    assert raw_client.get("/api/health").json()["email_enabled"] is True


def test_forgot_reset_roundtrip(client, raw_client, monkeypatch):
    sent = _enable_email(monkeypatch)
    r = raw_client.post("/api/auth/forgot", json={"email": "admin@acme.com"})
    assert r.status_code == 200 and len(sent) == 1
    token = _token(sent[0][2], "reset")

    ok = raw_client.post("/api/auth/reset", json={"token": token, "password": "brand-new-pw-9"})
    assert ok.status_code == 200
    # old password dead, new one works
    assert raw_client.post("/api/auth/login", json={
        "email": "admin@acme.com", "password": "password123"}).status_code == 401
    assert raw_client.post("/api/auth/login", json={
        "email": "admin@acme.com", "password": "brand-new-pw-9"}).status_code == 200
    # the link is single-use (token_version bumped)
    again = raw_client.post("/api/auth/reset", json={"token": token, "password": "yet-another-99"})
    assert again.status_code == 400
    # the pre-reset session died with the bump
    assert client.get("/api/auth/me").status_code == 401


def test_forgot_never_reveals_and_respects_disabled(raw_client, monkeypatch):
    # disabled -> 200, nothing sent
    r = raw_client.post("/api/auth/forgot", json={"email": "admin@acme.com"})
    assert r.status_code == 200
    # enabled + unknown address -> identical 200, still nothing sent
    sent = _enable_email(monkeypatch)
    r = raw_client.post("/api/auth/forgot", json={"email": "ghost@nowhere.example"})
    assert r.status_code == 200 and sent == []


def test_join_confirm_flow_manual_approval(client, raw_client, monkeypatch):
    import app.domains as domains
    sent = _enable_email(monkeypatch)
    d = client.post("/api/domains", json={"domain": "acme.com"}).json()
    monkeypatch.setattr(domains, "_lookup_txt",
                        lambda name: [f"palivane-domain-verify={d['token']}"])
    client.post(f"/api/domains/{d['id']}/verify")

    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "newbie@acme.com", "password": "password123"})
    assert r.json()["status"] == "confirm_email"
    # not visible as approvable-yet-unverified? it IS listed, but unverified
    req = client.get("/api/join-requests").json()["requests"][0]
    assert req["email_verified"] is False
    confirm_url = _token(sent[-1][2], "join")

    resp = raw_client.get(f"/api/auth/join/confirm?token={confirm_url}", follow_redirects=False)
    assert resp.status_code in (302, 307) and "#join=verified" in resp.headers["location"]
    assert client.get("/api/join-requests").json()["requests"][0]["email_verified"] is True
    # the admin got a heads-up
    assert any("join request" in s[1].lower() for s in sent)

    # bad token bounces to invalid
    bad = raw_client.get("/api/auth/join/confirm?token=garbage", follow_redirects=False)
    assert "#join=invalid" in bad.headers["location"]

    # admin approves -> the requester hears back and can sign in
    rid = client.get("/api/join-requests").json()["requests"][0]["id"]
    assert client.post(f"/api/join-requests/{rid}/approve").status_code == 200
    to, subject, body = sent[-1]
    assert to == "newbie@acme.com" and "approved" in body.lower()
    assert raw_client.post("/api/auth/login", json={
        "email": "newbie@acme.com", "password": "password123"}).status_code == 200


def test_join_confirm_auto_approve_creates_account_only_after_click(client, raw_client, monkeypatch):
    import app.domains as domains
    sent = _enable_email(monkeypatch)
    d = client.post("/api/domains", json={"domain": "acme.com"}).json()
    monkeypatch.setattr(domains, "_lookup_txt",
                        lambda name: [f"palivane-domain-verify={d['token']}"])
    client.post(f"/api/domains/{d['id']}/verify")
    client.patch(f"/api/domains/{d['id']}", json={"auto_approve": True})

    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "auto@acme.com", "password": "password123"})
    # auto_approve no longer short-circuits: email confirmation comes first
    assert r.json()["status"] == "confirm_email"
    assert raw_client.post("/api/auth/login", json={
        "email": "auto@acme.com", "password": "password123"}).status_code == 401

    token = _token(sent[-1][2], "join")
    resp = raw_client.get(f"/api/auth/join/confirm?token={token}", follow_redirects=False)
    assert "#join=approved" in resp.headers["location"]
    assert raw_client.post("/api/auth/login", json={
        "email": "auto@acme.com", "password": "password123"}).status_code == 200


def test_invite_by_email(client, raw_client, monkeypatch):
    sent = _enable_email(monkeypatch)
    r = client.post("/api/users", json={"email": "invited@acme.com", "role": "analyst"})
    assert r.status_code == 200 and r.json()["invited"] is True
    assert "invited" in sent[0][1].lower() or "invited" in sent[0][2].lower()
    token = _token(sent[0][2], "reset")
    # account unusable until the link is used
    assert raw_client.post("/api/auth/login", json={
        "email": "invited@acme.com", "password": "anything-guess"}).status_code == 401
    assert raw_client.post("/api/auth/reset",
                           json={"token": token, "password": "my-chosen-pw-1"}).status_code == 200
    assert raw_client.post("/api/auth/login", json={
        "email": "invited@acme.com", "password": "my-chosen-pw-1"}).status_code == 200


def test_invite_requires_email_plane(client):
    r = client.post("/api/users", json={"email": "x@acme.com", "role": "analyst"})
    assert r.status_code == 400 and "invites are not" in r.json()["detail"]
