"""SaaS OAuth-grant connectors — credential storage, live-pull sync, and the Google
Workspace grant normalizer."""

from __future__ import annotations

import json

import pytest

from app import saas_connectors as sc
from app.models import SaasConnector


def _mk_connector(client, creds=None):
    r = client.post("/api/discovery/connectors", json={
        "platform": "google_workspace", "label": "prod",
        "credentials": creds or {"service_account_json": {"client_email": "sa@p.iam", "private_key": "k"},
                                 "admin_email": "admin@acme.com"}})
    assert r.status_code == 200, r.text
    return r.json()


def test_create_lists_and_redacts(client):
    c = _mk_connector(client)
    assert c["configured"] is True and "credentials" not in c
    listing = client.get("/api/discovery/connectors").json()
    assert [x["id"] for x in listing["connectors"]] == [c["id"]]
    assert "google_workspace" in listing["platforms"]
    assert "credential_fields" in listing["platforms"]["google_workspace"]


def test_credentials_encrypted_at_rest(client, db_factory):
    c = _mk_connector(client, creds={"service_account_json": {"client_email": "sa@p.iam",
                                                                  "private_key": "SUPERSECRET"},
                                         "admin_email": "admin@acme.com"})
    db = db_factory()
    row = db.query(SaasConnector).filter_by(id=c["id"]).first()
    db.close()
    assert "SUPERSECRET" not in (row.credentials_enc or "")
    assert row.credentials_enc            # something was stored


def test_create_upserts_same_platform_label(client):
    a = _mk_connector(client)
    b = _mk_connector(client)         # same platform+label -> same row, rotated credential
    assert a["id"] == b["id"]
    assert len(client.get("/api/discovery/connectors").json()["connectors"]) == 1


def test_sync_ingests_grants_into_discovery(client, monkeypatch):
    c = _mk_connector(client)
    monkeypatch.setitem(sc.PLATFORMS["google_workspace"], "fetch", lambda creds: [
        {"app_name": "ChatGPT for Slack", "app_id": "123", "user": "alice@acme.com",
         "provider": "google", "scopes": ["https://www.googleapis.com/auth/drive.readonly"]},
        {"app_name": "Some CRM", "app_id": "9", "user": "bob@acme.com",
         "provider": "google", "scopes": []},
    ])
    out = client.post(f"/api/discovery/connectors/{c['id']}/sync")
    assert out.status_code == 200, out.text
    body = out.json()
    assert body["ai_apps"] == 1 and body["unknown"] == 1 and body["broad_scope"] == 1
    inv = client.get("/api/discovery/inventory").json()
    chatgpt = next(t for t in inv["tools"] if t["tool"] == "ChatGPT")
    assert "oauth" in chatgpt["sources"]
    st = client.get("/api/discovery/connectors").json()["connectors"][0]
    assert st["last_sync_status"] == "ok" and st["last_sync_at"]


def test_sync_error_is_recorded_and_surfaced(client, monkeypatch):
    c = _mk_connector(client)
    def boom(creds):
        raise sc.ConnectorError("HTTP 403 from admin.googleapis.com: delegation not granted")
    monkeypatch.setitem(sc.PLATFORMS["google_workspace"], "fetch", boom)
    out = client.post(f"/api/discovery/connectors/{c['id']}/sync")
    assert out.status_code == 502 and "delegation" in out.json()["detail"]
    st = client.get("/api/discovery/connectors").json()["connectors"][0]
    assert st["last_sync_status"] == "error" and "delegation" in st["last_sync_detail"]


def test_unknown_platform_rejected(client):
    r = client.post("/api/discovery/connectors",
                    json={"platform": "carrier_pigeon", "credentials": {}})
    assert r.status_code == 400


def test_delete(client):
    c = _mk_connector(client)
    assert client.delete(f"/api/discovery/connectors/{c['id']}").status_code == 200
    assert client.get("/api/discovery/connectors").json()["connectors"] == []


def test_google_normalizer_shapes_grants(monkeypatch):
    """fetch_google_workspace: token exchange + user paging + per-user tokens -> grant dicts."""
    calls = []
    def fake_http(url, **kw):
        calls.append(url)
        if "oauth2.googleapis.com" in url:
            return {"access_token": "at"}
        if url.endswith("/tokens") or "/tokens?" in url:
            return {"items": [{"displayText": "Otter.ai", "clientId": "c1",
                               "scopes": ["https://www.googleapis.com/auth/calendar.readonly"]}]}
        return {"users": [{"primaryEmail": "u1@acme.com"}, {"primaryEmail": "u2@acme.com"}]}
    monkeypatch.setattr(sc, "_http_json", fake_http)
    monkeypatch.setattr(sc, "_google_access_token", lambda creds: "at")
    grants = sc.fetch_google_workspace({})
    assert len(grants) == 2
    assert grants[0] == {"app_name": "Otter.ai", "app_id": "c1", "user": "u1@acme.com",
                         "provider": "google",
                         "scopes": ["https://www.googleapis.com/auth/calendar.readonly"]}


def test_google_token_requires_complete_credentials():
    with pytest.raises(sc.ConnectorError):
        sc._google_access_token({"admin_email": "a@b.c"})   # no service account
    with pytest.raises(sc.ConnectorError):
        sc._google_access_token({"service_account_json": "not-json{", "admin_email": "a@b.c"})
