"""Microsoft Teams message scanning (collab surface): team/channel enumeration via Graph,
HTML body stripping, PII/PHI/secret findings, thread-reply coverage, delta-incremental sync,
opt-in chat scanning with cross-user dedupe, truncation budget, and error surfacing."""

from __future__ import annotations

import app.saas_connectors as sc

MS_CREDS = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}


def _mk(client, label="teams-dlp", creds=None):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "teams_messages", "label": label,
                          "credentials": creds or MS_CREDS})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _msg(mid, uid, text, *, html=False, mtype="message", deleted=False, reply_to=None):
    m = {"id": mid, "messageType": mtype,
         "from": {"user": {"id": uid, "displayName": "Someone"}},
         "body": {"contentType": "html" if html else "text", "content": text}}
    if deleted:
        m["deletedDateTime"] = "2026-01-01T00:00:00Z"
    if reply_to:
        m["replyToId"] = reply_to
    return m


def _fake_graph(monkeypatch, messages, *, replies=None, users=None, chats=None,
                chat_topics=None):
    """Wire _http_json to a canned Graph: one team, one channel, the given delta window.
    `replies` maps root message id -> reply list; `chats` maps UPN -> chat message list.
    Returns the list of called URLs for delta/cursor assertions."""
    calls = []
    users = users or {"U1": "nurse@acme.com"}
    replies = replies or {}
    chats = chats or {}
    chat_topics = chat_topics or {}

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return {"access_token": "tok"}
        if "/groups?" in url:
            return {"value": [{"id": "T1", "displayName": "Acme"}]}
        if url.endswith("/teams/T1/channels"):
            return {"value": [{"id": "C1", "displayName": "general"}]}
        if "/messages/delta" in url or "%24deltatoken" in url:
            return {"value": messages,
                    "@odata.deltaLink": f"{sc._GRAPH_BASE}/teams/T1/channels/C1/messages/"
                                        "delta?%24deltatoken=NEXT"}
        if "/replies" in url:
            root = url.split("/messages/")[1].split("/replies")[0]
            return {"value": replies.get(root, [])}
        if "/chats/getAllMessages" in url:
            upn = url.split("/users/")[1].split("/chats")[0]
            return {"value": chats.get(upn, [])}
        if "/chats/" in url and "$select=topic" in url:
            cid = url.split("/chats/")[1].split("?")[0]
            return chat_topics.get(cid, {"topic": None, "chatType": "oneOnOne"})
        if "/users/" in url and "userPrincipalName" in url:
            uid = url.split("/users/")[1].split("?")[0]
            return {"userPrincipalName": users.get(uid, uid)}
        raise AssertionError(f"unexpected Graph call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)
    return calls


def test_teams_messages_platform_listed(client):
    platforms = client.get("/api/discovery/connectors").json()["platforms"]
    assert platforms["teams_messages"]["credential_fields"] == [
        "tenant_id", "client_id", "client_secret"]
    assert "ChannelMessage.Read.All" in platforms["teams_messages"]["setup"]


def test_scan_finds_phi_and_maps_actor(client, monkeypatch):
    _fake_graph(monkeypatch, [
        _msg("M1", "U1", "patient MRN 4859302 admitted, diagnosis E11.9"),
        _msg("M2", "U1", "lunch anyone?"),
    ])
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["teams"] == 1 and summary["channels"] == 1
    assert summary["messages"] == 2 and summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert len(rows) == 1
    f = rows[0]
    assert f["channel"] == "teams" and f["subject"] == "Acme/#general"
    assert f["sender"] == "nurse@acme.com"            # Graph user id mapped to UPN
    assert "phi_exposure" in f["categories"]


def test_html_bodies_are_stripped_before_detection(client, monkeypatch):
    _fake_graph(monkeypatch, [
        _msg("M1", "U1",
             "<p>customer SSN <b>078-05-1120</b>, card 4242&nbsp;4242 4242 4242</p>",
             html=True),
    ])
    cid = _mk(client)
    assert client.post(f"/api/discovery/connectors/{cid}/sync").json()["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert "pii_exposure" in rows[0]["categories"]
    assert "<p>" not in (rows[0].get("content") or "")


def test_thread_replies_are_scanned(client, monkeypatch):
    _fake_graph(monkeypatch,
                [_msg("M1", "U1", "kicking off the deploy thread")],
                replies={"M1": [_msg("R1", "U1",
                                     "prod key is AKIAIOSFODNN7EXAMPLE please don't share",
                                     reply_to="M1")]})
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["messages"] == 2 and summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert "secret_leak" in rows[0]["categories"]


def test_delta_link_stored_and_second_sync_is_incremental(client, monkeypatch):
    calls = _fake_graph(monkeypatch, [
        _msg("M1", "U1", "patient MRN 4859302 admitted, diagnosis E11.9"),
    ])
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    first = next(u for u in calls if "/messages/delta" in u)
    assert "lastModifiedDateTime" in first             # first sync bounded by lookback

    # Second sync: nothing new — the stored deltaLink must be used, not the lookback.
    calls = _fake_graph(monkeypatch, [])
    summary2 = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary2["messages"] == 0 and summary2["findings"] == 0
    delta_call = next(u for u in calls if "deltatoken" in u)
    assert "%24deltatoken=NEXT" in delta_call
    assert len(client.get("/api/findings?surface=collab").json()["findings"]) == 1


def test_system_events_and_deleted_messages_are_skipped(client, monkeypatch):
    _fake_graph(monkeypatch, [
        _msg("M1", "U1", "user added to channel", mtype="systemEventMessage"),
        _msg("M2", "U1", "SSN 078-05-1120", deleted=True),
        {"id": "M3", "messageType": "message", "from": {},        # bot / no user
         "body": {"contentType": "text", "content": "SSN 078-05-1120"}},
    ])
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["messages"] == 0 and summary["findings"] == 0
    assert summary["skipped"] == 3


def test_scan_budget_truncates_and_keeps_old_delta(client, monkeypatch):
    monkeypatch.setattr(sc, "_MAX_MESSAGES_PER_SYNC", 1)
    _fake_graph(monkeypatch, [
        _msg("M1", "U1", "patient MRN 4859302 admitted, diagnosis E11.9"),
        _msg("M2", "U1", "customer SSN 078-05-1120"),
    ])
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["truncated"] is True and summary["messages"] == 1
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    row = next(c for c in rows if c["id"] == cid)
    assert row["last_sync_status"] == "ok"


def test_chat_users_scanned_and_deduped_across_parties(client, monkeypatch):
    leak = _msg("CM1", "U1", "here's the db password hunter2 and key AKIAIOSFODNN7EXAMPLE")
    leak["chatId"] = "19:chat1"
    _fake_graph(monkeypatch, [],
                chats={"a%40acme.com": [leak], "b%40acme.com": [leak]},
                chat_topics={"19:chat1": {"topic": None, "chatType": "oneOnOne"}})
    cid = _mk(client, creds={**MS_CREDS, "chat_users": "a@acme.com, b@acme.com"})
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["chats"] == 1 and summary["findings"] == 1   # same message, one finding
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert rows[0]["subject"] == "1:1 chat" and rows[0]["channel"] == "teams"


def test_chat_pull_failure_does_not_discard_channel_results(client, monkeypatch):
    calls = []

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return {"access_token": "tok"}
        if "/groups?" in url:
            return {"value": [{"id": "T1", "displayName": "Acme"}]}
        if url.endswith("/teams/T1/channels"):
            return {"value": [{"id": "C1", "displayName": "general"}]}
        if "/messages/delta" in url:
            return {"value": [_msg("M1", "U1", "patient MRN 4859302, diagnosis E11.9")],
                    "@odata.deltaLink": "next"}
        if "/replies" in url:
            return {"value": []}
        if "/users/" in url and "userPrincipalName" in url:
            return {"userPrincipalName": "nurse@acme.com"}
        if "/chats/getAllMessages" in url:
            raise sc.ConnectorError("HTTP 402: payment model required")
        raise AssertionError(f"unexpected Graph call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)
    cid = _mk(client, creds={**MS_CREDS, "chat_users": ["a@acme.com"]})
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["findings"] == 1                    # channel finding survives
    assert summary["chat_errors"] == 1                 # failure surfaced, not swallowed


def test_missing_creds_and_api_error_surface(client, monkeypatch):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "teams_messages", "label": "bad", "credentials": {}})
    cid = r.json()["id"]
    assert client.post(f"/api/discovery/connectors/{cid}/sync").status_code == 502

    monkeypatch.setattr(sc, "_http_json", lambda url, **kw: (_ for _ in ()).throw(
        sc.ConnectorError("HTTP 403 from graph.microsoft.com: protected API not approved")))
    cid2 = _mk(client, label="denied")
    assert client.post(f"/api/discovery/connectors/{cid2}/sync").status_code == 502
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    bad = next(c for c in rows if c["label"] == "denied")
    assert bad["last_sync_status"] == "error" and "protected API" in bad["last_sync_detail"]


def test_scan_fingerprints_substantial_messages(client, monkeypatch, db_factory):
    long_msg = ("Here is the full production incident postmortem for the billing outage "
                "including the root cause analysis timeline and the customer accounts "
                "that were affected during the ninety minute window on tuesday morning")
    _fake_graph(monkeypatch, [
        _msg("M1", "U1", long_msg),
        _msg("M2", "U1", "lunch?"),
    ])
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    from app.models import ContentFingerprint, Tenant
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    rows = db.query(ContentFingerprint).filter_by(tenant_id=tid, source="teams").all()
    assert len(rows) == 1                              # only the substantial message
    assert rows[0].shingles and rows[0].owner == "nurse@acme.com"
    db.close()
