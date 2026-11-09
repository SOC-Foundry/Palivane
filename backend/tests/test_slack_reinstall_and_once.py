"""A reinstall keeps the connector's admin token and switches; each remediation action runs
at most once per Slack message, however many times the message is scanned."""
from __future__ import annotations

import urllib.parse
from types import SimpleNamespace

from app import saas_connectors as sc
from app import slack_install
from app import slack_remediation as sr


def test_reinstall_keeps_the_admin_token_and_switches(client, db_factory, monkeypatch):
    me = client.get("/api/auth/me").json()
    tenant_id = me["user"].get("tenant_id") or me["tenant"]["id"]
    tokens = iter(["xox" + "b-" + "1" * 12, "xox" + "b-" + "9" * 12])
    monkeypatch.setattr("app.saas_connectors._http_json", lambda url, data=None, headers=None: {
        "ok": True, "access_token": next(tokens), "team": {"id": "T1", "name": "acme"}, "app_id": "A1"})
    db = db_factory()
    try:
        def install():
            url, nonce = slack_install.install_url(tenant_id, "https://x/cb")
            state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
            return slack_install.complete_install(db, "code", state, "https://x/cb", nonce)
        row = install()
        sc.merge_options(row, {"admin_token": "xox" + "p-" + "2" * 12, "remediate": True,
                               "notify_sender": True, "alert_channel": "#sec"}, db)
        db.commit()
        row = install()                                    # the reinstall
        creds = sc.read_credentials(row, db)
        assert creds["bot_token"].endswith("9" * 12)        # the new bot token...
        assert creds["admin_token"].startswith("xox" + "p-")  # ...and everything else kept
        assert creds["remediate"] and creds["notify_sender"] and creds["alert_channel"] == "#sec"
    finally:
        db.close()


class FakeSlack:
    def __init__(self):
        self.calls = []

    def __call__(self, method, token, params):
        self.calls.append(method)
        return True, "", {"ok": True, "channel": {"id": "D1"}}


RESULT = {"finding_id": 1, "severity": "high",
          "signals": [{"category": "pii_exposure", "check": "pii_exposure", "detector": "shadow_ai",
                       "title": "Personal data in outbound content", "evidence": "SSN"}]}


def _run(monkeypatch, done: set[str], creds: dict):
    slack = FakeSlack()
    monkeypatch.setattr(sr, "_api", slack)
    monkeypatch.setattr(sr, "_done_before", lambda db, tid, target: done)
    monkeypatch.setattr(sr, "admin_token", lambda *a: "xox" + "p-t")
    monkeypatch.setattr(sr.audit_log, "record", lambda *a, **k: None)
    out = sr.remediate(SimpleNamespace(rollback=lambda: None), SimpleNamespace(id=1, tenant_id=1, label="a"),
                       {"bot_token": "xox" + "b-t", **creds}, channel="C1", where="#test",
                       ts="1.1", user_id="U1", actor="a", text="ssn on file", result=RESULT)
    return slack.calls, out


def test_a_second_scan_does_not_notify_again(monkeypatch):
    calls, out = _run(monkeypatch, {"slack.sender_notified"}, {"notify_sender": True})
    assert calls == [] and not out["notified"]


def test_a_deleted_message_is_left_alone(monkeypatch):
    calls, _ = _run(monkeypatch, {"slack.message_deleted"},
                    {"notify_sender": True, "remediate": True, "alert_channel": "#sec"})
    assert calls == []


def test_the_first_scan_still_acts(monkeypatch):
    calls, out = _run(monkeypatch, set(), {"notify_sender": True, "remediate": True})
    assert calls == ["chat.delete", "conversations.open", "chat.postMessage"] and out["deleted"]


def test_history_comes_from_the_audit_log(client, db_factory):
    from app import audit_log
    me = client.get("/api/auth/me").json()
    tenant_id = me["user"].get("tenant_id") or me["tenant"]["id"]
    db = db_factory()
    try:
        audit_log.record(db, tenant_id, "a", "slack.sender_notified", "#test:1.1", {})
        audit_log.record(db, tenant_id, "a", "slack.message_delete_failed", "#test:1.1", {})
        assert sr._done_before(db, tenant_id, "#test:1.1") == {"slack.sender_notified"}
        assert sr._done_before(db, tenant_id, "#test:2.2") == set()
    finally:
        db.close()
