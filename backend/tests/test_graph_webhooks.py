"""On-write SharePoint/OneDrive scanning: subscription lifecycle during sync (create /
renew / surface failures), the Graph validation handshake, clientState authentication,
notification-triggered per-drive delta scans, and debounce."""

from __future__ import annotations

import json

import app.saas_connectors as sc
import app.webhooks_graph as wg
from app.config import settings

MS_CREDS = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}
PUBLIC = "https://app.palivane.example"


def _mk(client, label="sp"):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "sharepoint_files", "label": label,
                          "credentials": MS_CREDS})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _fake_graph(monkeypatch, *, files=None, subs_created=None):
    """One site, one drive; canned delta; capture subscription POSTs."""
    calls = []
    subs_created = subs_created if subs_created is not None else []

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return {"access_token": "tok"}
        if "/sites?" in url:
            return {"value": [{"id": "S1"}]}
        if url.endswith("/sites/S1/drives"):
            return {"value": [{"id": "D1", "name": "Documents"}]}
        if "/root/delta" in url or "deltatoken" in url:
            return {"value": files or [], "@odata.deltaLink":
                    f"{sc._GRAPH_BASE}/drives/D1/root/delta?deltatoken=NEXT"}
        if url.endswith("/subscriptions"):
            subs_created.append(json.loads(data))
            return {"id": f"sub-{len(subs_created)}"}
        if "/subscriptions/" in url:
            return {"id": url.rsplit("/", 1)[1]}   # renewal PATCH
        if "/items/" in url and url.endswith("/content"):
            return {}
        raise AssertionError(f"unexpected Graph call: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)
    return calls, subs_created


def test_sync_creates_subscriptions_when_public_url_set(client, monkeypatch):
    monkeypatch.setattr(sc.settings, "public_base_url", PUBLIC)
    _, created = _fake_graph(monkeypatch)
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["subs_created"] == 1
    body = created[0]
    assert body["notificationUrl"] == f"{PUBLIC}/api/webhooks/graph"
    assert body["resource"] == "/drives/D1/root"
    assert body["clientState"]          # the signed routing token
    # stored for the webhook to route by
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    assert rows[0]["last_sync_status"] == "ok"


def test_sync_without_public_url_is_pull_only(client, monkeypatch):
    monkeypatch.setattr(sc.settings, "public_base_url", "")
    _, created = _fake_graph(monkeypatch)
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert "subs_created" not in summary and created == []


def test_subscription_failure_is_surfaced_not_fatal(client, monkeypatch):
    monkeypatch.setattr(sc.settings, "public_base_url", PUBLIC)
    calls = []

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return {"access_token": "tok"}
        if "/sites?" in url:
            return {"value": [{"id": "S1"}]}
        if url.endswith("/sites/S1/drives"):
            return {"value": [{"id": "D1", "name": "Documents"}]}
        if "/root/delta" in url:
            return {"value": [], "@odata.deltaLink": "next"}
        if url.endswith("/subscriptions"):
            raise sc.ConnectorError("HTTP 400: notificationUrl unreachable")
        raise AssertionError(f"unexpected: {url}")

    monkeypatch.setattr(sc, "_http_json", fake_http)
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["subs_errors"] == 1          # visible, and the scan still succeeded
    assert summary["files"] == 0


def test_validation_handshake_echoes_token(client):
    r = client.post("/api/webhooks/graph?validationToken=abc123%20xyz")
    assert r.status_code == 200
    assert r.text == "abc123 xyz"
    assert r.headers["content-type"].startswith("text/plain")


def test_notification_triggers_targeted_scan(client, monkeypatch, db_factory):
    monkeypatch.setattr(sc.settings, "public_base_url", PUBLIC)
    monkeypatch.setattr(wg, "_submit", lambda fn, *a: fn(*a))
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "SessionLocal", db_factory)
    wg._RECENT.clear()

    # sync once: subscription sub-1 exists, delta watermark stored
    _, created = _fake_graph(monkeypatch)
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    client_state = created[0]["clientState"]

    # now a file with PII lands; Graph notifies
    leak = {"id": "F1", "name": "customers.csv", "size": 100,
            "file": {"mimeType": "text/csv"},
            "lastModifiedBy": {"user": {"email": "ops@acme.com"}}}
    def fake_http(url, headers=None, data=None, timeout=20):
        if "login.microsoftonline.com" in url:
            return {"access_token": "tok"}
        if "deltatoken" in url or "/root/delta" in url:
            return {"value": [leak], "@odata.deltaLink": "next2"}
        if url.endswith("/content"):
            raise AssertionError("content fetched via _fetch_doc_text below")
        raise AssertionError(f"unexpected: {url}")
    monkeypatch.setattr(sc, "_http_json", fake_http)
    monkeypatch.setattr(sc, "_fetch_doc_text",
                        lambda url, hdrs, name, mime: ("SSN 078-05-1120, card 4242 4242 4242 4242",
                                                       False))

    r = client.post("/api/webhooks/graph", json={"value": [
        {"subscriptionId": "sub-1", "clientState": client_state}]})
    assert r.status_code == 202
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert len(rows) == 1
    assert rows[0]["channel"] == "sharepoint" and rows[0]["sender"] == "ops@acme.com"
    assert "customers.csv" in rows[0]["subject"]


def test_bad_clientstate_is_dropped_quietly(client, monkeypatch, db_factory):
    monkeypatch.setattr(wg, "_submit", lambda fn, *a: fn(*a))
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "SessionLocal", db_factory)
    r = client.post("/api/webhooks/graph", json={"value": [
        {"subscriptionId": "sub-x", "clientState": "forged-token"}]})
    assert r.status_code == 202                  # Graph must not retry garbage
    assert client.get("/api/findings?surface=collab").json()["findings"] == []


def _verify_failures(receiver):
    from app.metrics import WEBHOOK_VERIFY_FAILURES
    return WEBHOOK_VERIFY_FAILURES.labels(receiver)._value.get()


def test_bad_clientstate_is_counted_and_a_flood_is_dropped_unread(client, monkeypatch, caplog):
    """SEC-05: a forgery gets the same 202 as a real notification, so it is counted per source
    IP (and in the metric). Past the limit the IP is logged once and its deliveries are dropped
    before any token is decoded; the answer stays 202."""
    import app.security as sec
    wg._FAILS.clear()
    wg._WARNED.clear()
    before = _verify_failures("graph")
    forged = {"value": [{"subscriptionId": "s", "clientState": "forged"}] * 3}
    for _ in range(wg._FAIL_LIMIT // 3):
        assert client.post("/api/webhooks/graph", json=forged).status_code == 202
    assert _verify_failures("graph") - before == (wg._FAIL_LIMIT // 3) * 3
    assert sum("failed verification" in r.getMessage() for r in caplog.records) == 1
    assert "forged" not in caplog.text                       # never logs the token

    decoded = []
    real = sec.decode_token
    monkeypatch.setattr(sec, "decode_token", lambda t: decoded.append(t) or real(t))
    for _ in range(5):
        assert client.post("/api/webhooks/graph", json=forged).status_code == 202
    assert decoded == []                                      # dropped before decoding
    assert sum("failed verification" in r.getMessage() for r in caplog.records) == 1
    wg._FAILS.clear()
    wg._WARNED.clear()


def test_graph_body_that_is_not_a_notification_list_is_counted(client):
    wg._FAILS.clear()
    before = _verify_failures("graph")
    assert client.post("/api/webhooks/graph", content=b"not json",
                       headers={"content-type": "application/json"}).status_code == 202
    assert client.post("/api/webhooks/graph", json=["x"]).status_code == 202
    assert client.post("/api/webhooks/graph", json={"value": ["x", 1]}).status_code == 202
    assert _verify_failures("graph") - before == 4
    wg._FAILS.clear()


def test_gdrive_bad_channel_token_is_counted_and_sync_handshake_is_not(client, monkeypatch):
    from app.security import create_token
    monkeypatch.setattr(wg, "_submit", lambda fn, *a: None)
    wg._FAILS.clear()
    before = _verify_failures("gdrive")
    r = client.post("/api/webhooks/gdrive", headers={"X-Goog-Channel-Token": "forged",
                                                     "X-Goog-Resource-State": "change"})
    assert r.status_code == 200
    assert _verify_failures("gdrive") - before == 1
    ok = create_token({"typ": "gdrive_watch", "connector_id": 7})
    r = client.post("/api/webhooks/gdrive", headers={"X-Goog-Channel-Token": ok,
                                                     "X-Goog-Resource-State": "sync"})
    assert r.status_code == 200
    assert _verify_failures("gdrive") - before == 1          # a real handshake is not a failure
    wg._FAILS.clear()


def test_notification_burst_is_debounced(client, monkeypatch, db_factory):
    monkeypatch.setattr(sc.settings, "public_base_url", PUBLIC)
    monkeypatch.setattr(wg, "_submit", lambda fn, *a: fn(*a))
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "SessionLocal", db_factory)
    wg._RECENT.clear()

    _, created = _fake_graph(monkeypatch)
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    client_state = created[0]["clientState"]

    scans = []
    monkeypatch.setattr(sc, "_scan_drive",
                        lambda *a, **k: scans.append(1) or (0, 0, 0, False))
    note = {"subscriptionId": "sub-1", "clientState": client_state}
    for _ in range(5):
        client.post("/api/webhooks/graph", json={"value": [note]})
    assert len(scans) == 1                       # one pass covers the whole burst
