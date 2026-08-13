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


# --- Microsoft 365 / Entra ID -------------------------------------------------------------

_MS_CREDS = {"tenant_id": "t1", "client_id": "app", "client_secret": "s3cret"}


def test_microsoft_normalizer_shapes_grants(monkeypatch):
    """fetch_microsoft_365: token + SP enumeration + delegated grants (principal resolved
    to UPN) + app-role assignments (role GUIDs resolved to names) -> grant dicts."""
    def fake_http(url, **kw):
        if "login.microsoftonline.com" in url:
            return {"access_token": "at"}
        if "/servicePrincipals?" in url:
            return {"value": [
                {"id": "sp1", "appId": "aaa-111", "displayName": "ChatGPT", "appRoles": []},
                {"id": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000",
                 "displayName": "Microsoft Graph",
                 "appRoles": [{"id": "role-1", "value": "Mail.Read"}]},
            ]}
        if "/oauth2PermissionGrants" in url:
            return {"value": [
                {"clientId": "sp1", "consentType": "Principal", "principalId": "u1",
                 "scope": "Files.Read offline_access"},
                {"clientId": "sp1", "consentType": "AllPrincipals", "principalId": None,
                 "scope": "User.Read"},
            ]}
        if "/users/u1" in url:
            return {"userPrincipalName": "alice@acme.com"}
        if "/servicePrincipals/sp1/appRoleAssignments" in url:
            return {"value": [{"resourceId": "sp-graph", "appRoleId": "role-1"}]}
        if "/appRoleAssignments" in url:
            return {"value": []}
        raise AssertionError(f"unexpected URL {url}")
    monkeypatch.setattr(sc, "_http_json", fake_http)
    grants = sc.fetch_microsoft_365(_MS_CREDS)
    assert grants == [
        {"app_name": "ChatGPT", "app_id": "aaa-111", "user": "alice@acme.com",
         "provider": "microsoft", "scopes": ["Files.Read", "offline_access"]},
        {"app_name": "ChatGPT", "app_id": "aaa-111", "user": "",
         "provider": "microsoft", "scopes": ["User.Read"]},   # tenant-wide consent, no user
        {"app_name": "ChatGPT", "app_id": "aaa-111", "user": "",
         "provider": "microsoft", "scopes": ["Mail.Read"]},   # application grant
    ]


def test_microsoft_empty_tenant(monkeypatch):
    def fake_http(url, **kw):
        if "login.microsoftonline.com" in url:
            return {"access_token": "at"}
        return {"value": []}
    monkeypatch.setattr(sc, "_http_json", fake_http)
    assert sc.fetch_microsoft_365(_MS_CREDS) == []


def test_microsoft_auth_failures(monkeypatch):
    with pytest.raises(sc.ConnectorError):                    # incomplete credentials
        sc._microsoft_access_token({"tenant_id": "t1", "client_id": "app"})
    monkeypatch.setattr(sc, "_http_json",
                        lambda url, **kw: {"error": "invalid_client"})
    with pytest.raises(sc.ConnectorError):                    # token exchange denied
        sc.fetch_microsoft_365(_MS_CREDS)


# --- Slack ---------------------------------------------------------------------------------

def test_slack_normalizer_shapes_grants(monkeypatch):
    """fetch_slack: admin.apps.approved.list pages via cursor; org-level approvals carry
    no granting user."""
    pages = [
        {"ok": True,
         "approved_apps": [{"app": {"id": "A1", "name": "Claude"},
                            "scopes": [{"name": "channels:history"}, {"name": "chat:write"}]}],
         "response_metadata": {"next_cursor": "c2"}},
        {"ok": True,
         "approved_apps": [{"app": {"id": "A2", "name": "Some CRM"}, "scopes": []}],
         "response_metadata": {"next_cursor": ""}},
    ]
    seen = []
    def fake_http(url, **kw):
        seen.append(url)
        return pages[len(seen) - 1]
    monkeypatch.setattr(sc, "_http_json", fake_http)
    grants = sc.fetch_slack({"admin_token": "xoxp-admin", "team_id": "T123"})
    assert grants == [
        {"app_name": "Claude", "app_id": "A1", "user": "", "provider": "slack",
         "scopes": ["channels:history", "chat:write"]},
        {"app_name": "Some CRM", "app_id": "A2", "user": "", "provider": "slack", "scopes": []},
    ]
    assert "team_id=T123" in seen[0] and "cursor=c2" in seen[1]


def test_slack_empty(monkeypatch):
    monkeypatch.setattr(sc, "_http_json", lambda url, **kw: {"ok": True, "approved_apps": []})
    assert sc.fetch_slack({"admin_token": "xoxp-admin"}) == []


def test_slack_auth_failures(monkeypatch):
    with pytest.raises(sc.ConnectorError):
        sc.fetch_slack({})                                    # no token at all
    monkeypatch.setattr(sc, "_http_json",
                        lambda url, **kw: {"ok": False, "error": "missing_scope"})
    with pytest.raises(sc.ConnectorError, match="admin.apps:read"):
        sc.fetch_slack({"admin_token": "xoxp-weak"})          # ok:false carries a hint


# --- Salesforce ----------------------------------------------------------------------------

_SF_CREDS = {"instance_url": "https://acme.my.salesforce.com",
             "client_id": "cid", "client_secret": "cs"}


def test_salesforce_normalizer_shapes_grants(monkeypatch):
    """fetch_salesforce: client-credentials token, then OauthToken query with pagination.
    Salesforce exposes no per-token scopes, so scopes is always []."""
    def fake_http(url, **kw):
        if url.endswith("/services/oauth2/token"):
            return {"access_token": "at", "instance_url": "https://acme.my.salesforce.com"}
        if "/query?" in url:
            return {"done": False, "nextRecordsUrl": "/services/data/v60.0/query/next-1",
                    "records": [{"AppName": "Gong", "AppMenuItemId": "0Sc1",
                                 "User": {"Username": "alice@acme.com"}}]}
        if url.endswith("/query/next-1"):
            return {"done": True,
                    "records": [{"AppName": "Data Loader", "AppMenuItemId": None, "User": None}]}
        raise AssertionError(f"unexpected URL {url}")
    monkeypatch.setattr(sc, "_http_json", fake_http)
    grants = sc.fetch_salesforce(_SF_CREDS)
    assert grants == [
        {"app_name": "Gong", "app_id": "0Sc1", "user": "alice@acme.com",
         "provider": "salesforce", "scopes": []},
        {"app_name": "Data Loader", "app_id": "", "user": "",
         "provider": "salesforce", "scopes": []},
    ]


def test_salesforce_empty(monkeypatch):
    def fake_http(url, **kw):
        if url.endswith("/services/oauth2/token"):
            return {"access_token": "at"}
        return {"done": True, "records": []}
    monkeypatch.setattr(sc, "_http_json", fake_http)
    assert sc.fetch_salesforce(_SF_CREDS) == []


def test_salesforce_auth_failures(monkeypatch):
    with pytest.raises(sc.ConnectorError):                    # incomplete credentials
        sc.fetch_salesforce({"instance_url": "https://acme.my.salesforce.com"})
    monkeypatch.setattr(sc, "_http_json",
                        lambda url, **kw: {"error": "invalid_grant"})
    with pytest.raises(sc.ConnectorError):                    # token exchange denied
        sc.fetch_salesforce(_SF_CREDS)


# --- Notion (manual export only) -----------------------------------------------------------

def test_notion_is_manual_only():
    """No admin API exists for enumerating Notion OAuth grants — the registered stub must
    say so and point at the manual ingest, never pretend to sync."""
    assert sc.PLATFORMS["notion"]["manual_only"] is True
    assert sc.PLATFORMS["notion"]["credential_fields"] == []
    with pytest.raises(sc.ConnectorError, match="oauth-grants"):
        sc.fetch_notion({})


def test_notion_sync_surfaces_manual_only_error(client):
    r = client.post("/api/discovery/connectors", json={"platform": "notion", "credentials": {}})
    assert r.status_code == 200
    out = client.post(f"/api/discovery/connectors/{r.json()['id']}/sync")
    assert out.status_code == 502 and "oauth-grants" in out.json()["detail"]


# --- registry ------------------------------------------------------------------------------

def test_platform_registry_is_well_formed(client):
    for key, p in sc.PLATFORMS.items():
        # grant-inventory platforms carry `fetch`; content scanners carry `scan`
        assert callable(p.get("fetch") or p.get("scan")), key
        assert p["label"] and p["setup"], key
        assert isinstance(p["credential_fields"], list), key
    listing = client.get("/api/discovery/connectors").json()["platforms"]
    assert set(listing) == set(sc.PLATFORMS)
    assert listing["notion"]["manual_only"] is True
    assert listing["microsoft_365"]["manual_only"] is False
    assert listing["microsoft_365"]["credential_fields"] == ["tenant_id", "client_id",
                                                             "client_secret"]
