"""Slack message scanning (collab surface): channel enumeration, PII/PHI/secret findings,
actor mapping, cursor-incremental sync, truncation budget, and error surfacing."""

from __future__ import annotations

import json

import app.saas_connectors as sc

BOT_CREDS = {"bot_token": "xoxb-test-token"}


def _mk(client, label="dlp"):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "slack_messages", "label": label,
                          "credentials": BOT_CREDS})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _fake_slack(monkeypatch, messages, users=None):
    """Wire _http_json to a canned Slack: one channel, the given history, users.info map.
    Returns the list of (url) calls for cursor assertions."""
    calls = []
    users = users or {"U1": {"profile": {"email": "nurse@acme.com"}, "real_name": "Nurse"}}

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append(url)
        if "users.conversations" in url:
            return {"ok": True, "channels": [{"id": "C1", "name": "care-team"}]}
        if "conversations.history" in url:
            return {"ok": True, "messages": messages}
        if "users.info" in url:
            uid = url.split("user=")[1].split("&")[0]
            return {"ok": True, "user": users.get(uid, {"profile": {}})}
        raise AssertionError(f"unexpected Slack call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)
    return calls


def test_scan_finds_phi_and_maps_actor(client, monkeypatch):
    _fake_slack(monkeypatch, [
        {"user": "U1", "ts": "1755100002.000100",
         "text": "patient MRN 4859302 admitted, diagnosis E11.9"},
        {"user": "U1", "ts": "1755100001.000100", "text": "lunch anyone?"},
    ])
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["channels"] == 1 and summary["messages"] == 2
    assert summary["findings"] == 1                       # benign lunch message not persisted
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert len(rows) == 1
    f = rows[0]
    assert f["channel"] == "slack" and f["subject"] == "#care-team"
    assert f["sender"] == "nurse@acme.com"                # Slack uid mapped to email
    assert "phi_exposure" in f["categories"]


def test_scan_finds_secrets_on_collab_surface(client, monkeypatch):
    _fake_slack(monkeypatch, [
        {"user": "U1", "ts": "1755100003.000100",
         "text": "prod key is AKIAIOSFODNN7EXAMPLE please don't share"},
    ])
    cid = _mk(client)
    assert client.post(f"/api/discovery/connectors/{cid}/sync").json()["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert "secret_leak" in rows[0]["categories"]


def test_cursor_advances_and_second_sync_is_incremental(client, monkeypatch):
    calls = _fake_slack(monkeypatch, [
        {"user": "U1", "ts": "1755100002.000100",
         "text": "patient MRN 4859302 admitted, diagnosis E11.9"},
    ])
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    first_hist = next(u for u in calls if "conversations.history" in u)
    assert "oldest=" in first_hist                        # first sync bounded by lookback

    # Second sync: nothing new — history must be requested from the stored watermark.
    calls.clear()
    monkeypatch.setattr(sc, "_http_json", lambda url, **kw: (
        calls.append(url) or (
            {"ok": True, "channels": [{"id": "C1", "name": "care-team"}]}
            if "users.conversations" in url else {"ok": True, "messages": []})))
    summary2 = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary2["messages"] == 0 and summary2["findings"] == 0
    hist = next(u for u in calls if "conversations.history" in u)
    assert "oldest=1755100002.000100" in hist              # cursor, not the 7-day lookback
    # and no duplicate finding was created
    assert len(client.get("/api/findings?surface=collab").json()["findings"]) == 1


def test_bot_and_empty_messages_are_skipped(client, monkeypatch):
    _fake_slack(monkeypatch, [
        {"user": "U1", "subtype": "channel_join", "ts": "3.0", "text": "joined"},
        {"bot_id": "B9", "ts": "2.0", "text": "patient MRN 4859302"},   # no user -> bot
        {"user": "U1", "ts": "1.0", "text": "   "},
    ])
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["messages"] == 0 and summary["findings"] == 0


def test_scan_budget_truncates_and_reports(client, monkeypatch):
    monkeypatch.setattr(sc, "_MAX_MESSAGES_PER_SYNC", 2)
    _fake_slack(monkeypatch, [
        {"user": "U1", "ts": f"175510000{i}.000100", "text": f"note {i}"}
        for i in range(5, 0, -1)                          # newest-first, like Slack
    ])
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["messages"] == 2 and summary["truncated"] is True
    # watermark only advanced past what was actually scanned (oldest two)
    row = client.get("/api/discovery/connectors").json()["connectors"][0]
    assert json.loads(row["last_sync_detail"])["truncated"] is True


def test_missing_token_and_api_error_surface(client, monkeypatch):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "slack_messages", "label": "bad", "credentials": {}})
    cid = r.json()["id"]
    assert client.post(f"/api/discovery/connectors/{cid}/sync").status_code == 502

    monkeypatch.setattr(sc, "_http_json",
                        lambda url, **kw: {"ok": False, "error": "invalid_auth"})
    cid2 = _mk(client, label="badtoken")
    assert client.post(f"/api/discovery/connectors/{cid2}/sync").status_code == 502
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    bad = next(c for c in rows if c["label"] == "badtoken")
    assert bad["last_sync_status"] == "error" and "invalid_auth" in bad["last_sync_detail"]


def test_slack_messages_platform_listed(client):
    platforms = client.get("/api/discovery/connectors").json()["platforms"]
    assert platforms["slack_messages"]["credential_fields"] == ["bot_token"]
