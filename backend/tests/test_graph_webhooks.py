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
                        lambda url, hdrs, name, mime: "SSN 078-05-1120, card 4242 4242 4242 4242")

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
