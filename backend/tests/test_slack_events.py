"""Real-time Slack Events API endpoint: signature verification, URL handshake, redelivery
fold, team->connector resolution, message scanning parity with the pull sync, and the
off-by-default posture."""

from __future__ import annotations

import hmac
import json
import time
from hashlib import sha256

import app.saas_connectors as sc
import app.slack_events as se
from app.config import settings

SECRET = "test-signing-secret"


def _sign(body: bytes, ts: str | None = None, secret: str = SECRET):
    ts = ts or str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig,
            "Content-Type": "application/json"}


def _post(client, payload: dict, headers=None):
    body = json.dumps(payload).encode()
    return client.post("/api/slack/events", content=body, headers=headers or _sign(body))


def _mk_connector(client):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "slack_messages", "label": "dlp",
                          "credentials": {"bot_token": "xoxb-test"}})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _wire(monkeypatch, db_factory, *, inline=True):
    """Route worker-pool submits inline, point the worker's own session at the test DB,
    and wire Slack's API to canned responses."""
    if inline:
        monkeypatch.setattr(se, "_submit", lambda fn, *a: fn(*a))
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "SessionLocal", db_factory)
    monkeypatch.setattr(settings, "slack_signing_secret", SECRET)
    se._SEEN.clear()

    def fake_http(url, headers=None, data=None, timeout=20):
        if "auth.test" in url:
            return {"ok": True, "team_id": "T1"}
        if "conversations.info" in url:
            return {"ok": True, "channel": {"name": "care-team"}}
        if "users.info" in url:
            return {"ok": True,
                    "user": {"profile": {"email": "nurse@acme.com"}, "real_name": "Nurse"}}
        raise AssertionError(f"unexpected Slack call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)


def _event(text, *, team="T1", eid="Ev1", **extra):
    return {"type": "event_callback", "team_id": team, "event_id": eid,
            "event": {"type": "message", "user": "U1", "channel": "C1",
                      "ts": "1755100002.000100", "text": text, **extra}}


def test_endpoint_off_without_signing_secret(client, monkeypatch):
    monkeypatch.setattr(settings, "slack_signing_secret", "")
    assert _post(client, {"type": "url_verification"}).status_code == 400


def test_url_verification_handshake(client, monkeypatch):
    monkeypatch.setattr(settings, "slack_signing_secret", SECRET)
    r = _post(client, {"type": "url_verification", "challenge": "chal-123"})
    assert r.status_code == 200 and r.json()["challenge"] == "chal-123"


def test_bad_signature_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "slack_signing_secret", SECRET)
    body = json.dumps({"type": "url_verification", "challenge": "x"}).encode()
    assert client.post("/api/slack/events", content=body,
                       headers=_sign(body, secret="wrong")).status_code == 401


def test_stale_timestamp_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "slack_signing_secret", SECRET)
    body = json.dumps({"type": "url_verification", "challenge": "x"}).encode()
    stale = str(int(time.time()) - 3600)
    assert client.post("/api/slack/events", content=body,
                       headers=_sign(body, ts=stale)).status_code == 401


def test_message_event_creates_finding_with_actor_and_channel(client, monkeypatch, db_factory):
    _wire(monkeypatch, db_factory)
    _mk_connector(client)
    r = _post(client, _event("patient MRN 4859302 admitted, diagnosis E11.9"))
    assert r.status_code == 200
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert len(rows) == 1
    f = rows[0]
    assert f["channel"] == "slack" and f["subject"] == "#care-team"
    assert f["sender"] == "nurse@acme.com"
    assert "phi_exposure" in f["categories"]


def test_redelivered_event_id_is_folded(client, monkeypatch, db_factory):
    _wire(monkeypatch, db_factory)
    _mk_connector(client)
    _post(client, _event("customer SSN 078-05-1120", eid="EvSame"))
    _post(client, _event("customer SSN 078-05-1120", eid="EvSame"))
    assert len(client.get("/api/findings?surface=collab").json()["findings"]) == 1


def test_unknown_workspace_is_acked_and_dropped(client, monkeypatch, db_factory):
    _wire(monkeypatch, db_factory)
    _mk_connector(client)                        # connector maps to T1 via auth.test
    r = _post(client, _event("customer SSN 078-05-1120", team="T-OTHER"))
    assert r.status_code == 200                  # always ack — Slack must not retry
    assert client.get("/api/findings?surface=collab").json()["findings"] == []


def test_bot_and_subtype_messages_are_ignored(client, monkeypatch, db_factory):
    _wire(monkeypatch, db_factory)
    _mk_connector(client)
    _post(client, _event("SSN 078-05-1120", eid="Ev-b", bot_id="B1"))
    _post(client, _event("SSN 078-05-1120", eid="Ev-s", subtype="message_changed"))
    assert client.get("/api/findings?surface=collab").json()["findings"] == []


def test_team_id_learned_once_then_cached(client, monkeypatch, db_factory):
    _wire(monkeypatch, db_factory)
    cid = _mk_connector(client)
    _post(client, _event("patient MRN 4859302, diagnosis E11.9"))
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    row = next(c for c in rows if c["id"] == cid)
    # the workspace mapping was cached on the connector by the first event
    calls = []
    monkeypatch.setattr(sc, "_http_json", lambda url, **kw: (
        calls.append(url) or {"ok": True, "channel": {"name": "care-team"},
                              "user": {"profile": {"email": "nurse@acme.com"}}}))
    _post(client, _event("more text, nothing sensitive", eid="Ev2"))
    assert not any("auth.test" in u for u in calls)


def test_non_message_events_acked_without_processing(client, monkeypatch, db_factory):
    _wire(monkeypatch, db_factory)
    payload = {"type": "event_callback", "team_id": "T1", "event_id": "Ev-r",
               "event": {"type": "reaction_added"}}
    assert _post(client, payload).status_code == 200
