"""Slack Discovery connector (Enterprise Grid): reads every conversation org-wide
(public, private, DMs, group DMs) via the Discovery API, watermark-incremental, with an
unreadable conversation skipped rather than fatal."""

from __future__ import annotations

import app.saas_connectors as sc

CREDS = {"discovery_token": "xoxp-grid-discovery"}


def _mk(client, label="grid"):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "slack_discovery", "label": label,
                          "credentials": CREDS})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _fake(monkeypatch, channels, history, *, users=None, deny=()):
    """Canned Discovery API: conversations.list -> channels; conversations.history ->
    history[channel_id]; users.info -> users map. `deny` = channel ids that 200 ok:false."""
    users = users or {"U1": {"profile": {"email": "dev@acme.com"}}}

    def fake_http(url, headers=None, data=None, timeout=20):
        if "discovery.conversations.list" in url:
            return {"ok": True, "channels": channels}
        if "discovery.conversations.history" in url:
            cid = url.split("channel=")[1].split("&")[0]
            if cid in deny:
                return {"ok": False, "error": "channel_not_found"}
            return {"ok": True, "messages": history.get(cid, [])}
        if "users.info" in url:
            uid = url.split("user=")[1].split("&")[0]
            return {"ok": True, "user": users.get(uid, {"profile": {}})}
        raise AssertionError(f"unexpected Slack call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)


def test_platform_listed_grid_and_discovery_scope(client):
    p = client.get("/api/discovery/connectors").json()["platforms"]["slack_discovery"]
    assert p["credential_fields"] == ["discovery_token"]
    assert "discovery:read" in p["setup"] and "Enterprise Grid" in p["setup"]


def test_private_channel_and_dm_are_scanned(client, monkeypatch):
    _fake(monkeypatch,
          channels=[{"id": "C1", "name": "board", "is_private": True, "team_id": "T1"},
                    {"id": "D1", "is_im": True, "team_id": "T1"}],
          history={"C1": [{"user": "U1", "ts": "1755100002.0001",
                           "text": "customer SSN 078-05-1120, card 4242 4242 4242 4242"}],
                   "D1": [{"user": "U1", "ts": "1755100003.0001",
                           "text": "prod key AKIAIOSFODNN7EXAMPLE don't tell anyone"}]})
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["conversations"] == 2 and summary["messages"] == 2
    assert summary["findings"] == 2
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    subjects = {r["subject"] for r in rows}
    assert any("private #board" == s for s in subjects)
    assert "DM" in subjects
    assert all(r["channel"] == "slack" for r in rows)


def test_unreadable_conversation_skipped_not_fatal(client, monkeypatch):
    _fake(monkeypatch,
          channels=[{"id": "C1", "name": "ok", "team_id": "T1"},
                    {"id": "CX", "name": "denied", "is_private": True, "team_id": "T1"}],
          history={"C1": [{"user": "U1", "ts": "1755100004.0001",
                           "text": "SSN 078-05-1120"}]},
          deny=("CX",))
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["findings"] == 1 and summary["skipped"] == 1


def test_watermark_advances_and_second_sync_incremental(client, monkeypatch):
    _fake(monkeypatch,
          channels=[{"id": "C1", "name": "care", "team_id": "T1"}],
          history={"C1": [{"user": "U1", "ts": "1755100009.0001",
                           "text": "patient MRN 4859302 diagnosis E11.9"}]})
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    # second sync: history now empty (all consumed) — no new findings, no dupes
    _fake(monkeypatch, channels=[{"id": "C1", "name": "care", "team_id": "T1"}], history={"C1": []})
    s2 = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert s2["messages"] == 0
    assert len(client.get("/api/findings?surface=collab").json()["findings"]) == 1


def test_missing_token_errors(client):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "slack_discovery", "label": "bad", "credentials": {}})
    cid = r.json()["id"]
    assert client.post(f"/api/discovery/connectors/{cid}/sync").status_code == 502
