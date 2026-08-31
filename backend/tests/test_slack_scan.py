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


def test_scan_finds_pii_on_collab_surface(client, monkeypatch):
    _fake_slack(monkeypatch, [
        {"user": "U1", "ts": "1755100004.000100",
         "text": "customer SSN 078-05-1120, card 4242 4242 4242 4242"},
    ])
    cid = _mk(client)
    assert client.post(f"/api/discovery/connectors/{cid}/sync").json()["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert "pii_exposure" in rows[0]["categories"]


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


def test_scan_fingerprints_substantial_messages(client, monkeypatch, db_factory):
    """Slack scanning stores content-origin fingerprints for real messages (so a later
    leak traces back to the thread), and skips one-liners too short to shingle."""
    long_msg = ("Here is the full production incident postmortem for the billing outage "
                "including the root cause analysis timeline and the customer accounts "
                "that were affected during the ninety minute window on tuesday morning")
    _fake_slack(monkeypatch, [
        {"user": "U1", "ts": "1755100003.000100", "text": long_msg},
        {"user": "U1", "ts": "1755100001.000100", "text": "lunch?"},
    ])
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    from app.models import ContentFingerprint, Tenant
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    rows = db.query(ContentFingerprint).filter_by(tenant_id=tid, source="slack").all()
    assert len(rows) == 1                       # only the substantial message
    assert rows[0].shingles and rows[0].owner == "nurse@acme.com"
    db.close()


# --- auto-join: the closest a bot token gets to the Enterprise Grid view -------------------
# Default stays invite-only. With auto_join the bot enumerates every public channel and
# joins the ones it is not in — because a channel nobody invited it to is simply invisible,
# which is the single most common reason a first scan comes back near-empty.

def _fake_workspace(monkeypatch, public, private=(), history=None, joins=None):
    history = history or []

    def fake_http(url, headers=None, data=None, timeout=20):
        if "conversations.list" in url:
            return {"ok": True, "channels": list(public)}
        if "users.conversations" in url:
            want_private = "private_channel" in url and "public_channel" not in url
            return {"ok": True, "channels": list(private) if want_private
                    else [c for c in public if c.get("is_member")] + list(private)}
        if "conversations.join" in url:
            cid = (data or b"").decode().split("channel=")[1]
            if joins is not None:
                joins.append(cid)
            return {"ok": True} if cid != "C_LOCKED" else {"ok": False, "error": "is_archived"}
        if "conversations.history" in url:
            return {"ok": True, "messages": history}
        if "users.info" in url:
            return {"ok": True, "user": {"profile": {"email": "dev@acme.com"}}}
        raise AssertionError(f"unexpected Slack call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)


def test_default_scans_only_invited_channels(monkeypatch):
    joins = []
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "in", "is_member": True},
                            {"id": "C2", "name": "out", "is_member": False}],
                    joins=joins)
    channels, joined = sc._slack_channels({}, auto_join=False)
    assert [c["id"] for c in channels] == ["C1"]
    assert joined == 0 and joins == [], "must not touch the workspace unless asked"


def test_auto_join_covers_every_public_channel(monkeypatch):
    joins = []
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "in", "is_member": True},
                            {"id": "C2", "name": "out", "is_member": False},
                            {"id": "C3", "name": "also-out", "is_member": False}],
                    joins=joins)
    channels, joined = sc._slack_channels({}, auto_join=True)
    assert sorted(c["id"] for c in channels) == ["C1", "C2", "C3"]
    assert sorted(joins) == ["C2", "C3"] and joined == 2   # already-in is not re-joined


def test_a_channel_that_refuses_the_join_is_dropped_not_fatal(monkeypatch):
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "ok", "is_member": True},
                            {"id": "C_LOCKED", "name": "nope", "is_member": False}])
    channels, joined = sc._slack_channels({}, auto_join=True)
    assert [c["id"] for c in channels] == ["C1"] and joined == 0


def test_auto_join_never_reaches_private_channels(monkeypatch):
    """No bot scope opens a private conversation — only Discovery API does, and that is
    Enterprise Grid. Private coverage stays exactly what was invited in."""
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "pub", "is_member": False}],
                    private=[{"id": "G1", "name": "invited-private"}])
    channels, _ = sc._slack_channels({}, auto_join=True)
    assert sorted(c["id"] for c in channels) == ["C1", "G1"]   # G1 only because invited


# --- attachments ---------------------------------------------------------------------------
# A regulated record is as likely to be a pasted CSV as a typed sentence.

def test_readable_file_types():
    assert sc._slack_readable_file({"filetype": "csv"})
    assert sc._slack_readable_file({"mimetype": "text/plain"})
    assert not sc._slack_readable_file({"filetype": "pdf", "mimetype": "application/pdf"})
    assert not sc._slack_readable_file({"filetype": "png", "mimetype": "image/png"})


def test_attachment_is_scanned_as_its_own_finding(client, monkeypatch):
    """The message may be innocuous while the file it carries is not, so the file gets its
    own finding, subject-named so triage points at the thing to delete."""
    cid = _mk(client, "files")
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "care-team", "is_member": True}],
                    history=[{"user": "U1", "ts": "1755100003.000100", "text": "as discussed",
                              "files": [{"id": "F1", "name": "export.csv", "filetype": "csv",
                                         "size": 120, "url_private_download": "https://x/f"}]}])
    monkeypatch.setattr(sc, "_slack_file_text",
                        lambda f, h: "name,ssn\nJane Roe,412-88-7390\n")
    r = client.post(f"/api/discovery/connectors/{cid}/sync")
    assert r.status_code == 200, r.text
    detail = r.json()
    assert detail["files"] == 1 and detail["findings"] >= 1


def test_unreadable_attachment_is_counted_not_silently_dropped(client, monkeypatch):
    """PDFs, Office docs and images are a real gap. The sync detail has to say so rather
    than reporting a clean scan over files it never opened."""
    cid = _mk(client, "binary")
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "care-team", "is_member": True}],
                    history=[{"user": "U1", "ts": "1755100004.000100", "text": "scan attached",
                              "files": [{"id": "F2", "name": "chart.pdf", "filetype": "pdf",
                                         "mimetype": "application/pdf", "size": 900,
                                         "url_private_download": "https://x/f"}]}])
    detail = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert detail.get("files_skipped") == 1 and "files" not in detail


def test_oversize_attachment_is_skipped(client, monkeypatch):
    cid = _mk(client, "big")
    _fake_workspace(monkeypatch,
                    public=[{"id": "C1", "name": "care-team", "is_member": True}],
                    history=[{"user": "U1", "ts": "1755100005.000100", "text": "logs",
                              "files": [{"id": "F3", "name": "huge.log", "filetype": "log",
                                         "size": sc._MAX_FILE_BYTES + 1,
                                         "url_private_download": "https://x/f"}]}])
    detail = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert detail.get("files_skipped") == 1


# --- toggling auto_join without re-sending the token ----------------------------------------

def test_options_round_trip_without_the_credential(client, db_factory):
    """The switch must be flippable from the console. Requiring the bot token again to
    change a checkbox is how a token ends up in a browser autofill or a support ticket."""
    cid = _mk(client, "opts")
    listed = client.get("/api/discovery/connectors").json()["connectors"]
    row = next(c for c in listed if c["id"] == cid)
    assert row["options"] == {"auto_join": False}

    r = client.patch(f"/api/discovery/connectors/{cid}", json={"auto_join": True})
    assert r.status_code == 200 and r.json()["options"]["auto_join"] is True

    # and the token survived the edit
    from app.models import SaasConnector
    db = db_factory()
    conn = db.get(SaasConnector, cid)
    assert sc.read_credentials(conn, db)["bot_token"] == BOT_CREDS["bot_token"]
    db.close()


def test_options_never_leak_the_token(client):
    cid = _mk(client, "leak")
    body = client.get("/api/discovery/connectors").text
    assert BOT_CREDS["bot_token"] not in body
    assert BOT_CREDS["bot_token"] not in client.patch(
        f"/api/discovery/connectors/{cid}", json={"auto_join": True}).text


def test_partial_patch_does_not_clear_what_it_omits(client):
    cid = _mk(client, "partial")
    client.patch(f"/api/discovery/connectors/{cid}", json={"auto_join": True})
    r = client.patch(f"/api/discovery/connectors/{cid}", json={})
    assert r.json()["options"]["auto_join"] is True


def test_patch_rejects_an_unknown_connector(client):
    """The lookup is filtered by tenant_id, so another org's id is simply not found."""
    assert client.patch("/api/discovery/connectors/999999",
                        json={"auto_join": True}).status_code == 404
