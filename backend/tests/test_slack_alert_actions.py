"""The security team's Slack alert: blocks, signed buttons, and what a click may do.
Slack is faked; nothing leaves the test. Values are assembled from fragments."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from types import SimpleNamespace

import pytest

from app import slack_interactions as si
from app import slack_remediation as sr

KEY = "AK" + "IA" + "Q3EGT7XP5RLVN2KD"
RESULT = {"finding_id": 11, "severity": "critical",
          "signals": [{"category": "secret_leak", "check": "secret_leak", "detector": "shadow_ai",
                       "title": "Credentials/secrets in outbound content",
                       "evidence": "AWS access key id", "weight": 0.9, "confidence": 0.9}]}
CONN = SimpleNamespace(id=5, tenant_id=1, label="acme")
LOC = dict(channel="C1", where="#ops", ts="1700000000.000100", user_id="U9", actor="dev@acme.com")


class FakeSlack:
    def __init__(self, fail=None):
        self.calls, self.fail = [], dict(fail or {})

    def __call__(self, method, token, params):
        self.calls.append((method, token, dict(params)))
        if self.fail.get(method):
            return False, self.fail.pop(method), {}
        if method == "conversations.open":
            return True, "", {"ok": True, "channel": {"id": "D1"}}
        if method == "conversations.join":
            return True, "", {"ok": True, "channel": {"id": "C777"}}
        return True, "", {"ok": True}


def _actions(blocks):
    return [e["action_id"].split(":", 1)[1] for b in blocks if b["type"] == "actions" for e in b["elements"]]


def test_buttons_offer_only_what_has_not_been_done():
    blocks = sr.alert_blocks(CONN, result=RESULT, done={}, can_change=True, **LOC)
    assert _actions(blocks) == ["redact", "delete", "notify", "dismiss"]
    assert "AWS access key id" in blocks[0]["text"]["text"] and KEY not in json.dumps(blocks)
    after = sr.alert_blocks(CONN, result=RESULT, done={"deleted": True, "notified": True},
                            can_change=True, **LOC)
    assert _actions(after) == ["dismiss"] and "deleted, sender notified" in json.dumps(after)
    no_token = sr.alert_blocks(CONN, result=RESULT, done={}, can_change=False, **LOC)
    assert _actions(no_token) == ["notify", "dismiss"]


def test_button_values_are_signed():
    value = sr.alert_blocks(CONN, result=RESULT, done={}, can_change=True, **LOC)[-1]["elements"][1]["value"]
    fields = sr.unsign_action(value)
    assert fields["a"] == "delete" and fields["c"] == "C1" and fields["t"] == LOC["ts"] and fields["k"] == 5
    body, _, mac = value.rpartition(".")
    assert sr.unsign_action(body[:-2] + "AA." + mac) is None
    assert sr.unsign_action("garbage") is None


def test_alert_joins_a_public_channel_it_was_not_invited_to(monkeypatch):
    slack = FakeSlack(fail={"chat.postMessage": "not_in_channel"})
    monkeypatch.setattr(sr, "_api", slack)
    ok, _ = sr.post_alert(CONN, {"bot_token": "xoxb-t", "alert_channel": "#security"},
                          result=RESULT, done={}, can_change=True, **LOC)
    assert ok and [c[0] for c in slack.calls] == ["chat.postMessage", "conversations.join", "chat.postMessage"]
    assert slack.calls[-1][2]["channel"] == "C777"


# --- a click, end to end against the test database ---------------------------------------

@pytest.fixture
def world(client, db_factory, monkeypatch):
    """A Slack connector with an admin token, one critical finding, faked Slack."""
    r = client.post("/api/discovery/connectors", json={
        "platform": "slack_messages", "label": "acme",
        "credentials": {"bot_token": "xox" + "b-" + "1" * 12, "admin_token": "xox" + "p-" + "2" * 12}})
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    fid = client.post("/api/analyze", json={"content": f"deploy with {KEY}", "surface": "ai_usage",
                                            "persist": True}).json()["finding_id"]
    admin = client.get("/api/auth/me").json()["user"]["email"]
    from app.models import SaasConnector
    monkeypatch.setattr("app.slack_events._connector_for_team",
                        lambda db, *a: db.get(SaasConnector, cid))
    monkeypatch.setattr("app.plans.has_feature", lambda t, f: True)
    slack, said = FakeSlack(), []
    monkeypatch.setattr(sr, "_api", slack)
    monkeypatch.setattr(si, "_respond", lambda url, payload: said.append(payload))
    monkeypatch.setattr(si, "_message_text", lambda bot, c, ts: f"deploy with {KEY} tonight")
    clicker = {"email": admin}
    monkeypatch.setattr(si, "_clicker_email", lambda bot, uid: clicker["email"])
    return SimpleNamespace(cid=cid, fid=fid, slack=slack, said=said, clicker=clicker,
                           client=client, db_factory=db_factory)


def _click(w, action, value=None):
    fields = {"f": w.fid, "k": w.cid, "c": "C1", "t": LOC["ts"], "u": "U9", "w": "#ops", "a": action}
    payload = {"type": "block_actions", "team": {"id": "T1"}, "user": {"id": "UADMIN"},
               "response_url": "https://hooks.slack.com/actions/x",
               "message": {"text": "alert", "blocks": sr.alert_blocks(
                   SimpleNamespace(id=w.cid, tenant_id=1, label="acme"), result={**RESULT, "finding_id": w.fid},
                   done={}, can_change=True, **LOC)},
               "actions": [{"action_id": f"{sr.ALERT_ACTION_ID}:{action}",
                            "value": value or sr.sign_action(fields)}]}
    si.handle_click(payload, db_factory=w.db_factory)
    return w.said[-1] if w.said else None


def test_delete_from_the_alert(world):
    out = _click(world, "delete")
    assert [c[0] for c in world.slack.calls] == ["chat.delete"]
    assert world.slack.calls[0][1].startswith("xoxp-")          # the admin token, not the bot
    assert out["replace_original"] and "Deleted by" in json.dumps(out["blocks"])
    assert "delete" not in _actions(out["blocks"]) and "redact" not in _actions(out["blocks"])


def test_redact_from_the_alert_reads_the_message_back(world):
    _click(world, "redact")
    method, _, params = world.slack.calls[0]
    assert method == "chat.update" and KEY not in params["text"] and params["text"].endswith(" tonight")


def test_dismiss_from_the_alert_records_a_false_positive(world):
    out = _click(world, "dismiss")
    assert world.slack.calls == [] and _actions(out["blocks"]) == []
    row = next(f for f in world.client.get("/api/findings", params={"limit": 50}).json()["findings"]
               if f["id"] == world.fid)
    assert row["status"] == "dismissed"


def test_only_a_palivane_admin_may_click(world):
    world.clicker["email"] = "stranger@elsewhere.com"
    out = _click(world, "delete")
    assert world.slack.calls == [] and out["response_type"] == "ephemeral"
    assert "Only a Palivane admin" in out["text"]


def test_a_forged_button_changes_nothing(world):
    out = _click(world, "delete", value="eyJhIjoiZGVsZXRlIn0.0000")
    assert world.slack.calls == [] and "could not be verified" in out["text"]


def _signed_post(raw_client, secret, body: bytes):
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return raw_client.post("/api/slack/interactions", content=body,
                           headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig,
                                    "Content-Type": "application/x-www-form-urlencoded"})


def test_the_endpoint_checks_slacks_signature(raw_client, monkeypatch):
    secret = "s" * 32
    monkeypatch.setattr("app.config.settings.slack_signing_secret", secret)
    seen = []
    monkeypatch.setattr(si, "handle_click", lambda payload, db_factory=None: seen.append(payload))
    body = urllib.parse.urlencode({"payload": json.dumps({"type": "block_actions", "actions": []})}).encode()
    assert _signed_post(raw_client, secret, body).status_code == 200
    assert _signed_post(raw_client, "wrong" * 7, body).status_code == 401
    for _ in range(50):
        if seen:
            break
        time.sleep(0.02)
    assert len(seen) == 1
