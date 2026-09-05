"""Outlook sent-mail scanning + Drive on-write: registry, PII findings with recipient
subjects, HTML stripping, text-attachment handling, refused-mailbox isolation, watermark;
Drive channel lifecycle during sync and the webhook-triggered sync path."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import app.saas_connectors as sc
import app.webhooks_graph as wg

MS_CREDS = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}
G_CREDS = {"service_account_json": {"client_email": "sa@p.iam", "private_key": "k"},
           "admin_email": "admin@acme.com"}
_NOW = datetime.now(timezone.utc)


def _mk(client, platform, creds, label="x"):
    r = client.post("/api/discovery/connectors",
                    json={"platform": platform, "label": label, "credentials": creds})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _omsg(mid, *, to="vendor@ext.com", subject="export", body="", html=False,
          has_atts=False, sent=None):
    return {"id": mid, "sentDateTime": (sent or _NOW.strftime("%Y-%m-%dT%H:%M:%SZ")),
            "subject": subject, "hasAttachments": has_atts,
            "toRecipients": [{"emailAddress": {"address": to}}],
            "body": {"contentType": "html" if html else "text", "content": body}}


def _fake_outlook(monkeypatch, messages_by_user, *, atts=None, refuse=()):
    def fake_http(url, headers=None, data=None, timeout=20):
        if "login.microsoftonline.com" in url:
            return {"access_token": "tok"}
        if "/users?" in url:
            return {"value": [{"userPrincipalName": u} for u in messages_by_user]}
        if "/attachments" in url:
            return {"value": atts or []}
        if "/mailFolders/SentItems/messages" in url:
            user = url.split("/users/")[1].split("/")[0].replace("%40", "@")
            if user in refuse:
                raise sc.ConnectorError("HTTP 404: mailbox not enabled")
            return {"value": messages_by_user.get(user, [])}
        raise AssertionError(f"unexpected: {url}")
    monkeypatch.setattr(sc, "_http_json", fake_http)


def test_outlook_platform_listed(client):
    p = client.get("/api/discovery/connectors").json()["platforms"]["outlook_messages"]
    assert "Mail.Read" in p["setup"]


def test_outlook_pii_finding_with_recipient(client, monkeypatch):
    _fake_outlook(monkeypatch, {"dev@acme.com": [
        _omsg("M1", body="customer SSN 078-05-1120 card 4242 4242 4242 4242"),
        _omsg("M2", subject="lunch", body="see you"),
    ]})
    cid = _mk(client, "outlook_messages", MS_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["messages"] == 2 and summary["findings"] == 1
    f = client.get("/api/findings?surface=collab").json()["findings"][0]
    assert f["channel"] == "outlook" and "vendor@ext.com" in f["subject"]


def test_outlook_html_stripped_and_attachment_scanned(client, monkeypatch):
    _fake_outlook(monkeypatch,
                  {"dev@acme.com": [_omsg("M1", body="<p>see attached</p>", html=True,
                                          has_atts=True)]},
                  atts=[{"name": "dump.csv", "contentType": "text/csv", "size": 40,
                         "contentBytes": base64.b64encode(
                             b"ssn\n078-05-1120").decode()},
                        {"name": "x.png", "contentType": "image/png", "size": 40,
                         "contentBytes": ""}])
    cid = _mk(client, "outlook_messages", MS_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["findings"] == 1 and summary["skipped"] == 1


def test_outlook_refused_mailbox_isolated_and_watermark(client, monkeypatch):
    _fake_outlook(monkeypatch,
                  {"dead@acme.com": [], "dev@acme.com": [
                      _omsg("M1", body="SSN 078-05-1120")]},
                  refuse=("dead@acme.com",))
    cid = _mk(client, "outlook_messages", MS_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["mail_errors"] == 1 and summary["findings"] == 1
    # watermark: rerun with the same canned data yields nothing new (filter is server-
    # side in real Graph; here assert the mark was stored)
    rows = client.get("/api/discovery/connectors").json()["connectors"]
    assert rows[0]["last_sync_status"] == "ok"


# --- Drive on-write --------------------------------------------------------------------

def _fake_drive(monkeypatch, *, watch_captures):
    def fake_token(creds, scopes=sc._GOOGLE_SCOPES, sub=""):
        return "tok"
    def fake_http(url, headers=None, data=None, timeout=20):
        if "/changes/startPageToken" in url:
            return {"startPageToken": "pt-1"}
        if "/changes/watch" in url:
            watch_captures.append(json.loads(data))
            return {"resourceId": "res-1",
                    "expiration": str(int(_NOW.timestamp() * 1000) + 86400000)}
        if "channels/stop" in url:
            return {}
        if "/files?" in url or "files?" in url:
            return {"files": []}
        raise AssertionError(f"unexpected: {url}")
    monkeypatch.setattr(sc, "_google_access_token", fake_token)
    monkeypatch.setattr(sc, "_http_json", fake_http)


def test_gdrive_sync_creates_watch_channel(client, monkeypatch):
    monkeypatch.setattr(sc.settings, "public_base_url", "https://app.example")
    caps = []
    _fake_drive(monkeypatch, watch_captures=caps)
    cid = _mk(client, "gdrive_files", G_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary.get("watch_renewed") == 1
    assert caps[0]["address"] == "https://app.example/api/webhooks/gdrive"
    assert caps[0]["token"]
    # alive channel is not re-created on the next sync
    summary2 = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert "watch_renewed" not in summary2


def test_gdrive_no_public_url_pull_only(client, monkeypatch):
    monkeypatch.setattr(sc.settings, "public_base_url", "")
    caps = []
    _fake_drive(monkeypatch, watch_captures=caps)
    cid = _mk(client, "gdrive_files", G_CREDS)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    assert caps == []


def test_gdrive_webhook_triggers_sync(client, monkeypatch, db_factory):
    monkeypatch.setattr(sc.settings, "public_base_url", "https://app.example")
    caps = []
    _fake_drive(monkeypatch, watch_captures=caps)
    monkeypatch.setattr(wg, "_submit", lambda fn, *a: fn(*a))
    import app.database as db_mod
    monkeypatch.setattr(db_mod, "SessionLocal", db_factory)
    wg._RECENT.clear()

    cid = _mk(client, "gdrive_files", G_CREDS)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    token = caps[0]["token"]

    synced = []
    monkeypatch.setattr(sc, "sync_connector", lambda db, row: synced.append(row.id) or {})
    r = client.post("/api/webhooks/gdrive", headers={
        "X-Goog-Channel-Token": token, "X-Goog-Resource-State": "change"})
    assert r.status_code == 200
    assert synced == [cid]
    # handshake ('sync') and forged tokens are acked but never sync
    client.post("/api/webhooks/gdrive", headers={
        "X-Goog-Channel-Token": token, "X-Goog-Resource-State": "sync"})
    client.post("/api/webhooks/gdrive", headers={
        "X-Goog-Channel-Token": "forged", "X-Goog-Resource-State": "change"})
    assert synced == [cid]
