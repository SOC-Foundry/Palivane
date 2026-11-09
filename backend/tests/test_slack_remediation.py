"""Slack remediation: redact, delete, notify the sender — gates, fallbacks, and wording.
The Slack API is faked; nothing leaves the test. Values are assembled from fragments."""
from __future__ import annotations

import secrets
from types import SimpleNamespace

import pytest

from app import slack_remediation as sr

KEY = "AK" + "IA" + "Q3EGT7XP5RLVN2KD"
TEXT = f"deploy with {KEY} tonight"
RESULT = {"finding_id": 7, "severity": "critical",
          "signals": [{"category": "secret_leak", "check": "secret_leak",
                       "title": "Credentials/secrets in outbound content",
                       "evidence": "AWS access key id", "detector": "shadow_ai",
                       "weight": 0.9, "confidence": 0.9}]}
CONN = SimpleNamespace(id=3, tenant_id=1, label="acme")


class FakeSlack:
    def __init__(self, fail=()):
        self.calls, self.fail = [], dict(fail)

    def __call__(self, method, token, params):
        self.calls.append((method, token, dict(params)))
        if method in self.fail:
            return False, self.fail[method], {}
        if method == "conversations.open":
            return True, "", {"ok": True, "channel": {"id": "D123"}}
        return True, "", {"ok": True}

    def methods(self):
        return [c[0] for c in self.calls]


@pytest.fixture
def audit(monkeypatch):
    rec = []
    monkeypatch.setattr(sr.audit_log, "record", lambda db, tid, actor, action, target, detail: rec.append((action, detail)))
    return rec


def _run(monkeypatch, creds, slack, admin="xoxp-" + secrets.token_hex(8), result=RESULT, text=TEXT):
    monkeypatch.setattr(sr, "_api", slack)
    monkeypatch.setattr(sr, "admin_token", lambda db, c, cr: admin if (cr.get("redact") or cr.get("remediate")) else "")
    return sr.remediate(SimpleNamespace(rollback=lambda: None), CONN,
                        {"bot_token": "xoxb-" + secrets.token_hex(8), **creds},
                        channel="C1", where="#ops", ts="1700000000.000100", user_id="U9",
                        actor="dev@acme.com", text=text, result=result)


def test_nothing_runs_below_the_confirmed_tier(monkeypatch, audit):
    slack = FakeSlack()
    out = _run(monkeypatch, {"redact": True, "remediate": True, "notify_sender": True}, slack,
               result={**RESULT, "severity": "suspicious"})
    assert slack.calls == [] and audit == [] and not any(out[k] for k in ("redacted", "deleted", "notified"))


def test_redact_replaces_only_the_value(monkeypatch, audit):
    slack = FakeSlack()
    out = _run(monkeypatch, {"redact": True}, slack)
    assert out["redacted"] and slack.methods() == ["chat.update"]
    new_text = slack.calls[0][2]["text"]
    assert KEY not in new_text and new_text.startswith("deploy with ") and new_text.endswith(" tonight")
    assert audit[0][0] == "slack.message_redacted"


def test_redact_refused_outside_grid_falls_back_to_delete(monkeypatch, audit):
    slack = FakeSlack(fail={"chat.update": "cant_update_message"})
    out = _run(monkeypatch, {"redact": True, "remediate": True}, slack)
    assert not out["redacted"] and out["deleted"] and out["failed"] == ["redact"]
    assert slack.methods() == ["chat.update", "chat.delete"]
    assert [a for a, _ in audit] == ["slack.message_redact_failed", "slack.message_deleted"]
    assert "Enterprise Grid" in audit[0][1]["error"]


def test_redact_skips_a_value_with_no_exact_span(monkeypatch, audit):
    slack = FakeSlack()
    folded = "deploy with " + "".join(chr(ord(c) + 0xFEE0) for c in KEY)   # fullwidth: no raw span
    out = _run(monkeypatch, {"redact": True}, slack, text=folded)
    assert not out["redacted"] and "chat.update" not in slack.methods()
    assert audit[0][1]["error"] == "no_exact_span"


def test_delete_needs_the_admin_token(monkeypatch, audit):
    slack = FakeSlack()
    out = _run(monkeypatch, {"remediate": True}, slack, admin="")
    assert not out["deleted"] and slack.calls == []


@pytest.mark.parametrize("creds,word", [
    ({"notify_sender": True}, "Please delete it"),
    ({"notify_sender": True, "remediate": True}, "deleted your message"),
    ({"notify_sender": True, "redact": True}, "removed AWS access key id"),
], ids=["ask", "deleted", "redacted"])
def test_notice_says_what_happened_and_never_the_value(monkeypatch, audit, creds, word):
    slack = FakeSlack()
    out = _run(monkeypatch, creds, slack)
    assert out["notified"]
    open_call = next(c for c in slack.calls if c[0] == "conversations.open")
    post = next(c for c in slack.calls if c[0] == "chat.postMessage")
    assert open_call[2] == {"users": "U9"} and post[2]["channel"] == "D123"
    assert word in post[2]["text"] and "rotate" in post[2]["text"] and KEY not in post[2]["text"]
    assert post[1].startswith("xoxb-")                     # the bot posts, never the admin
    assert audit[-1][0] == "slack.sender_notified"


def test_a_failed_notice_is_recorded(monkeypatch, audit):
    slack = FakeSlack(fail={"chat.postMessage": "missing_scope"})
    out = _run(monkeypatch, {"notify_sender": True}, slack)
    assert not out["notified"] and out["failed"] == ["notify"]
    assert audit[-1][0] == "slack.sender_notify_failed" and audit[-1][1]["error"] == "missing_scope"


def test_labels_are_rule_names_only():
    assert sr.labels_of(RESULT) == ["AWS access key id"]
    masked = {**RESULT, "signals": [{**RESULT["signals"][0], "evidence": "AKIA••••N2KD"}]}
    assert sr.labels_of(masked) == ["Credentials/secrets in outbound content"]
