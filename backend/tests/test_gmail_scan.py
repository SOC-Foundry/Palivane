"""Gmail sent-mail scanning (collab surface): mailbox enumeration, per-user delegation,
MIME walking (plain/html/attachments), PII/secret findings, watermark-incremental sync,
per-mailbox failure isolation, and budget truncation."""

from __future__ import annotations

import base64
import time

import app.saas_connectors as sc

_NOW_MS = int(time.time() * 1000)

CREDS = {"service_account_json": {"client_email": "sa@p.iam", "private_key": "k"},
         "admin_email": "admin@acme.com"}


def _mk(client, label="mail"):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "gmail_messages", "label": label,
                          "credentials": CREDS})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _b64(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _msg(mid, *, to="vendor@external.com", subject="export", text="", html="",
         attachments=(), internal_ms=0):
    parts = []
    if text:
        parts.append({"mimeType": "text/plain", "body": {"data": _b64(text)}})
    if html:
        parts.append({"mimeType": "text/html", "body": {"data": _b64(html)}})
    for fname, mime, data, att_id in attachments:
        parts.append({"mimeType": mime, "filename": fname,
                      "body": {"size": len(data), "attachmentId": att_id}})
    return {"id": mid, "internalDate": str(internal_ms or _NOW_MS),
            "payload": {"headers": [{"name": "To", "value": to},
                                    {"name": "Subject", "value": subject}],
                        "mimeType": "multipart/mixed", "parts": parts}}


def _fake_gmail(monkeypatch, messages_by_user, *, attachments=None, token_fail=()):
    """Canned Admin SDK + Gmail: users are messages_by_user's keys."""
    calls = []
    attachments = attachments or {}

    def fake_token(creds, scopes=sc._GOOGLE_SCOPES, sub=""):
        if sub in token_fail:
            raise sc.ConnectorError("delegation refused")
        return f"tok-{sub or 'admin'}"

    def fake_http(url, headers=None, data=None, timeout=20):
        calls.append(url)
        auth = (headers or {}).get("Authorization", "")
        if "/admin/directory" in url:
            return {"users": [{"primaryEmail": u} for u in messages_by_user]}
        user = auth.replace("Bearer tok-", "")
        if "/messages?" in url:
            msgs = messages_by_user.get(user, [])
            import urllib.parse as up
            q = up.parse_qs(up.urlparse(url).query).get("q", [""])[0]
            after = int(q.split("after:")[1]) if "after:" in q else 0
            fresh = [m for m in msgs if int(m["internalDate"]) // 1000 > after]
            return {"messages": [{"id": m["id"]} for m in fresh]}
        if "/attachments/" in url:
            att_id = url.rsplit("/", 1)[1]
            return {"data": _b64(attachments.get(att_id, ""))}
        if "/messages/" in url:
            mid = url.split("/messages/")[1].split("?")[0]
            for msgs in messages_by_user.values():
                for m in msgs:
                    if m["id"] == mid:
                        return m
        raise AssertionError(f"unexpected call: {url}")

    monkeypatch.setattr(sc, "_google_access_token", fake_token)
    monkeypatch.setattr(sc, "_http_json", fake_http)
    return calls


def test_platform_listed(client):
    platforms = client.get("/api/discovery/connectors").json()["platforms"]
    assert platforms["gmail_messages"]["credential_fields"] == [
        "service_account_json", "admin_email"]
    assert "gmail.readonly" in platforms["gmail_messages"]["setup"]


def test_sent_mail_pii_becomes_finding_with_recipient_subject(client, monkeypatch):
    _fake_gmail(monkeypatch, {"dev@acme.com": [
        _msg("M1", to="vendor@external.com", subject="customer export",
             text="here you go: SSN 078-05-1120, card 4242 4242 4242 4242"),
        _msg("M2", subject="lunch", text="see you at noon"),
    ]})
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["users"] == 1 and summary["messages"] == 2
    assert summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    f = rows[0]
    assert f["channel"] == "gmail" and f["sender"] == "dev@acme.com"
    assert "vendor@external.com" in f["subject"] and "customer export" in f["subject"]
    assert "pii_exposure" in f["categories"]


def test_html_body_stripped_and_scanned(client, monkeypatch):
    _fake_gmail(monkeypatch, {"dev@acme.com": [
        _msg("M1", html="<p>prod key <b>AKIAIOSFODNN7EXAMPLE</b></p>"),
    ]})
    cid = _mk(client)
    assert client.post(f"/api/discovery/connectors/{cid}/sync").json()["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert "secret_leak" in rows[0]["categories"]


def test_text_attachment_scanned_binary_skipped(client, monkeypatch):
    _fake_gmail(monkeypatch,
                {"dev@acme.com": [_msg("M1", text="see attached",
                                       attachments=[
                                           ("dump.csv", "text/csv", "x" * 60, "A1"),
                                           ("logo.png", "image/png", "x" * 60, "A2")])]},
                attachments={"A1": "name,ssn\njane,078-05-1120"})
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["findings"] == 1
    assert summary["skipped"] == 1                 # the png: counted, never clean


def test_watermark_advances_per_mailbox(client, monkeypatch):
    _fake_gmail(monkeypatch, {"dev@acme.com": [
        _msg("M1", text="SSN 078-05-1120", internal_ms=_NOW_MS - 5000),
    ]})
    cid = _mk(client)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    # Second sync: same canned mailbox — the watermark must exclude the scanned mail.
    summary2 = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary2["messages"] == 0
    assert len(client.get("/api/findings?surface=collab").json()["findings"]) == 1


def test_refused_mailbox_counted_not_fatal(client, monkeypatch):
    _fake_gmail(monkeypatch,
                {"suspended@acme.com": [], "dev@acme.com": [
                    _msg("M1", text="SSN 078-05-1120")]},
                token_fail=("suspended@acme.com",))
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["mail_errors"] == 1 and summary["findings"] == 1


def test_budget_truncates(client, monkeypatch):
    monkeypatch.setattr(sc, "_MAX_MESSAGES_PER_SYNC", 1)
    _fake_gmail(monkeypatch, {"dev@acme.com": [
        _msg("M1", text="SSN 078-05-1120", internal_ms=_NOW_MS - 9000),
        _msg("M2", text="card 4242 4242 4242 4242", internal_ms=_NOW_MS - 4000),
    ]})
    cid = _mk(client)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["truncated"] is True and summary["messages"] == 1
