"""'Add to Slack' OAuth install flow: authorize URL + signed state, the unauthenticated
callback (code exchange, connector upsert, redirects), and failure paths."""

from __future__ import annotations

import urllib.parse

import app.saas_connectors as sc
import app.slack_install as si
from app.crypto import decrypt
from app.security import decode_token


def _configure(monkeypatch):
    monkeypatch.setattr(si.settings, "slack_client_id", "123.456")
    monkeypatch.setattr(si.settings, "slack_client_secret", "shhh")
    monkeypatch.setattr(si.settings, "slack_redirect_url",
                        "https://palivane.example/api/slack/oauth/callback")


def _fake_exchange(monkeypatch, response=None, calls=None):
    calls = calls if calls is not None else []

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append((url, data))
        return response if response is not None else {
            "ok": True, "access_token": "xoxb-installed-token",
            "team": {"id": "T1", "name": "Acme Health"}}
    monkeypatch.setattr(sc, "_http_json", fake_http)
    return calls


def test_install_url_carries_signed_tenant_state(client, monkeypatch):
    _configure(monkeypatch)
    r = client.get("/api/slack/install")
    assert r.status_code == 200
    url = r.json()["url"]
    assert url.startswith("https://slack.com/oauth/v2/authorize?")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["client_id"] == ["123.456"]
    assert "channels:history" in q["scope"][0] and "users:read.email" in q["scope"][0]
    state = decode_token(q["state"][0])
    assert state["typ"] == "slack_install" and state["tenant_id"] > 0


def test_install_404_when_no_published_app(client, monkeypatch):
    monkeypatch.setattr(si.settings, "slack_client_id", "")
    monkeypatch.setattr(si.settings, "slack_client_secret", "")
    assert client.get("/api/slack/install").status_code == 404


def test_callback_exchanges_code_and_creates_connector(client, raw_client, monkeypatch):
    _configure(monkeypatch)
    calls = _fake_exchange(monkeypatch)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(
        client.get("/api/slack/install").json()["url"]).query)["state"][0]
    # the callback is hit by the admin's BROWSER, unauthenticated — state carries tenancy
    r = raw_client.get(f"/api/slack/oauth/callback?code=c0de&state={state}",
                       follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/?slack=installed"
    # the code exchange hit Slack with the code + secret
    assert calls and b"code=c0de" in calls[0][1] and b"client_secret=shhh" in calls[0][1]
    # connector upserted with the workspace name, token encrypted at rest
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    conn = next(c for c in rows if c["platform"] == "slack_messages")
    assert conn["label"] == "Acme Health" and conn["configured"] is True
    # re-install (rotated token) upserts the same row rather than duplicating
    state2 = urllib.parse.parse_qs(urllib.parse.urlparse(
        client.get("/api/slack/install").json()["url"]).query)["state"][0]
    raw_client.get(f"/api/slack/oauth/callback?code=c0de2&state={state2}",
                   follow_redirects=False)
    rows2 = [c for c in client.get("/api/discovery/connectors").json()["connectors"]
             if c["platform"] == "slack_messages"]
    assert len(rows2) == 1


def test_callback_failure_paths_redirect_never_500(client, raw_client, monkeypatch):
    _configure(monkeypatch)
    # user hit "Cancel" on Slack's consent screen
    r = raw_client.get("/api/slack/oauth/callback?error=access_denied", follow_redirects=False)
    assert r.headers["location"] == "/?slack=denied"
    # bogus state
    r = raw_client.get("/api/slack/oauth/callback?code=x&state=garbage", follow_redirects=False)
    assert r.headers["location"] == "/?slack=error"
    # a session JWT is NOT an install state (typ mismatch must be rejected)
    session_jwt = client.headers["Authorization"].split(" ", 1)[1]
    r = raw_client.get(f"/api/slack/oauth/callback?code=x&state={session_jwt}",
                       follow_redirects=False)
    assert r.headers["location"] == "/?slack=error"
    # Slack refuses the exchange
    _fake_exchange(monkeypatch, response={"ok": False, "error": "invalid_code"})
    state = urllib.parse.parse_qs(urllib.parse.urlparse(
        client.get("/api/slack/install").json()["url"]).query)["state"][0]
    r = raw_client.get(f"/api/slack/oauth/callback?code=bad&state={state}",
                       follow_redirects=False)
    assert r.headers["location"] == "/?slack=error"


def test_org_wide_install_labels_from_enterprise(client, raw_client, monkeypatch):
    # Enterprise Grid org-wide install: team is null, enterprise carries the identity.
    _configure(monkeypatch)
    _fake_exchange(monkeypatch, response={
        "ok": True, "access_token": "xoxb-org-token",
        "team": None, "enterprise": {"id": "E1", "name": "Acme Health Org"}})
    state = urllib.parse.parse_qs(urllib.parse.urlparse(
        client.get("/api/slack/install").json()["url"]).query)["state"][0]
    r = raw_client.get(f"/api/slack/oauth/callback?code=c0de&state={state}",
                       follow_redirects=False)
    assert r.headers["location"] == "/?slack=installed"
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    conn = next(c for c in rows if c["platform"] == "slack_messages")
    assert conn["label"] == "Acme Health Org"


def test_installed_token_feeds_the_scanner(client, raw_client, monkeypatch, db_factory):
    """End-to-end: OAuth install stores the token the scanner then uses to pull Slack."""
    _configure(monkeypatch)
    _fake_exchange(monkeypatch)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(
        client.get("/api/slack/install").json()["url"]).query)["state"][0]
    raw_client.get(f"/api/slack/oauth/callback?code=c0de&state={state}", follow_redirects=False)
    db = db_factory()
    from app.models import SaasConnector
    row = db.query(SaasConnector).filter(SaasConnector.platform == "slack_messages").one()
    import json as _json
    assert _json.loads(decrypt(row.credentials_enc))["bot_token"] == "xoxb-installed-token"
    db.close()
