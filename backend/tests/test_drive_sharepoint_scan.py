"""Google Drive + SharePoint content scanning (collab surface): text extraction,
findings, watermark/delta cursors, skip rules, truncation budget."""

from __future__ import annotations

import app.saas_connectors as sc

GDRIVE_CREDS = {"service_account_json": {"client_email": "sa@x.iam", "private_key": "k"},
                "admin_email": "admin@acme.com"}
SP_CREDS = {"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"}


def _mk(client, platform, creds):
    r = client.post("/api/discovery/connectors",
                    json={"platform": platform, "label": "dlp", "credentials": creds})
    assert r.status_code == 200, r.text
    return r.json()["id"]


# --- Google Drive -------------------------------------------------------------------------

def _fake_gdrive(monkeypatch, files, contents):
    """Canned Drive API: files.list returns `files`, per-file content from `contents`."""
    monkeypatch.setattr(sc, "_google_access_token", lambda creds, scopes=None: "tok")

    def fake_json(url, headers=None, data=None, timeout=20):
        assert "/files?" in url
        return {"files": files}

    def fake_text(url, headers, cap=sc._MAX_CONTENT_BYTES):
        fid = url.split("/files/")[1].split("/")[0].split("?")[0]
        return contents[fid]

    monkeypatch.setattr(sc, "_http_json", fake_json)
    monkeypatch.setattr(sc, "_http_text", fake_text)


def test_gdrive_scan_finds_secrets_and_advances_watermark(client, monkeypatch):
    _fake_gdrive(monkeypatch, [
        {"id": "f1", "name": "notes.txt", "mimeType": "text/plain",
         "modifiedTime": "2026-08-20T10:00:00.000Z",
         "lastModifyingUser": {"emailAddress": "alice@acme.com"}},
        {"id": "f2", "name": "Budget", "modifiedTime": "2026-08-21T10:00:00.000Z",
         "mimeType": "application/vnd.google-apps.spreadsheet",
         "owners": [{"emailAddress": "bob@acme.com"}]},
        {"id": "f3", "name": "logo.png", "mimeType": "image/png",
         "modifiedTime": "2026-08-22T10:00:00.000Z"},
    ], {"f1": "db password: xK9mPq24Rt7Vw1Yz", "f2": "quarter,amount\nQ1,100"})
    cid = _mk(client, "gdrive_files", GDRIVE_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 2 and summary["skipped"] == 1   # png skipped
    assert summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    f = [r for r in rows if r["channel"] == "gdrive"][0]
    assert f["subject"] == "notes.txt" and f["sender"] == "alice@acme.com"
    assert "secret_leak" in f["categories"]


def test_gdrive_budget_truncates(client, monkeypatch):
    files = [{"id": f"f{i}", "name": f"n{i}.txt", "mimeType": "text/plain",
              "modifiedTime": f"2026-08-20T10:00:{i:02d}.000Z"} for i in range(5)]
    _fake_gdrive(monkeypatch, files, {f"f{i}": "hello world" for i in range(5)})
    monkeypatch.setattr(sc, "_MAX_FILES_PER_SYNC", 3)
    cid = _mk(client, "gdrive_files", GDRIVE_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 3 and summary.get("truncated") is True


# --- SharePoint ----------------------------------------------------------------------------

def _fake_graph(monkeypatch, items, contents):
    monkeypatch.setattr(sc, "_microsoft_access_token", lambda creds: "tok")

    def fake_json(url, headers=None, data=None, timeout=20):
        if "/sites?" in url:
            return {"value": [{"id": "site1", "name": "Eng"}]}
        if "/sites/site1/drives" in url:
            return {"value": [{"id": "d1", "name": "Documents"}]}
        if "/delta" in url:
            return {"value": items, "@odata.deltaLink": "https://graph/next-delta"}
        raise AssertionError(f"unexpected Graph call: {url}")

    def fake_text(url, headers, cap=sc._MAX_CONTENT_BYTES):
        iid = url.split("/items/")[1].split("/")[0]
        return contents[iid]

    monkeypatch.setattr(sc, "_http_json", fake_json)
    monkeypatch.setattr(sc, "_http_text", fake_text)


def test_sharepoint_scan_finds_pii_and_stores_delta(client, monkeypatch):
    _fake_graph(monkeypatch, [
        {"id": "i1", "name": "employees.csv", "size": 100,
         "file": {"mimeType": "text/csv"},
         "lastModifiedBy": {"user": {"email": "hr@acme.com"}}},
        {"id": "i2", "name": "photo.jpg", "size": 100, "file": {"mimeType": "image/jpeg"}},
        {"id": "i3", "name": "folder", "size": 0},   # no file facet
    ], {"i1": "name,ssn\njane doe,123-45-6789"})
    cid = _mk(client, "sharepoint_files", SP_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["sites"] == 1 and summary["drives"] == 1
    assert summary["files"] == 1 and summary["skipped"] == 1 and summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    f = [r for r in rows if r["channel"] == "sharepoint"][0]
    assert f["subject"] == "Documents/employees.csv" and f["sender"] == "hr@acme.com"
    assert "pii_exposure" in f["categories"]


def test_sharepoint_budget_keeps_old_delta(client, monkeypatch):
    items = [{"id": f"i{n}", "name": f"n{n}.txt", "size": 10,
              "file": {"mimeType": "text/plain"}} for n in range(4)]
    _fake_graph(monkeypatch, items, {f"i{n}": "hello" for n in range(4)})
    monkeypatch.setattr(sc, "_MAX_FILES_PER_SYNC", 2)
    cid = _mk(client, "sharepoint_files", SP_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 2 and summary.get("truncated") is True


def test_platforms_registered(client):
    """The registry rides inside the connectors list — the UI renders setup forms from
    it, so registering the platform IS the frontend work."""
    plats = client.get("/api/discovery/connectors").json()["platforms"]
    assert {"gdrive_files", "sharepoint_files"} <= set(plats)
    for k in ("gdrive_files", "sharepoint_files"):
        assert plats[k]["credential_fields"] and plats[k]["setup"]
