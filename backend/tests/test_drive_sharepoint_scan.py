"""Google Drive + SharePoint content scanning (collab surface): text extraction,
findings, watermark/delta cursors, skip rules, truncation budget."""

from __future__ import annotations

import urllib.parse

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

    def _for(url):
        return contents[url.split("/files/")[1].split("/")[0].split("?")[0]]

    def fake_text(url, headers, cap=sc._MAX_CONTENT_BYTES):
        return _for(url)                       # Google-native export -> text/plain

    def fake_bytes(url, headers, cap=sc._MAX_CONTENT_BYTES):
        # An uploaded file arrives as BYTES now, so a mislabelled binary can no longer be
        # decoded into replacement characters and scanned as if it were prose.
        body = _for(url)
        return body if isinstance(body, bytes) else body.encode()

    monkeypatch.setattr(sc, "_http_json", fake_json)
    monkeypatch.setattr(sc, "_http_text", fake_text)
    monkeypatch.setattr(sc, "_http_bytes", fake_bytes)


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

    def fake_bytes(url, headers, cap=sc._MAX_CONTENT_BYTES):
        body = contents[url.split("/items/")[1].split("/")[0]]
        return body if isinstance(body, bytes) else body.encode()

    monkeypatch.setattr(sc, "_http_json", fake_json)
    monkeypatch.setattr(sc, "_http_bytes", fake_bytes)


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


# --- Salesforce content ------------------------------------------------------------------

SF_CREDS = {"instance_url": "https://acme.my.salesforce.com",
            "client_id": "c1", "client_secret": "s1"}


def _fake_salesforce(monkeypatch, by_object):
    """Canned SOQL: by_object maps sObject name -> list of record dicts."""
    monkeypatch.setattr(sc, "_salesforce_access", lambda creds: ("https://acme.my.salesforce.com", "tok"))

    def fake_json(url, headers=None, data=None, timeout=20):
        q = sc.urllib.parse.unquote_plus(url.split("q=", 1)[1]) if "q=" in url else ""
        for name, recs in by_object.items():
            if f"FROM {name} " in q:
                return {"records": recs, "done": True}
        return {"records": [], "done": True}

    monkeypatch.setattr(sc, "_http_json", fake_json)


def test_salesforce_scans_cases_and_chatter(client, monkeypatch, db_factory):
    _fake_salesforce(monkeypatch, {
        "Case": [
            {"Id": "500x1", "LastModifiedDate": "2026-08-20T10:00:00.000+0000",
             "LastModifiedBy": {"Username": "agent@acme.com"},
             "Subject": "billing question",
             "Description": "customer SSN is 123-45-6789 and card 4111111111111111"},
            {"Id": "500x2", "LastModifiedDate": "2026-08-21T10:00:00.000+0000",
             "LastModifiedBy": {"Username": "agent@acme.com"},
             "Subject": "hello", "Description": "just checking in, no data here"},
        ],
        "FeedItem": [
            {"Id": "0D5x1", "LastModifiedDate": "2026-08-22T10:00:00.000+0000",
             "CreatedBy": {"Username": "rep@acme.com"},
             "Body": "posting the prod db password=Pr0dDb9xKmz2024 for the team"},
        ],
    })
    cid = _mk(client, "salesforce_content", SF_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["records"] == 3 and summary["objects"] == 2
    assert summary["findings"] == 2                      # the benign case doesn't persist
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    sf = [r for r in rows if r["channel"] == "salesforce"]
    assert len(sf) == 2
    case = [r for r in sf if r["subject"].startswith("Case:")][0]
    assert case["sender"] == "agent@acme.com" and "pii_exposure" in case["categories"]
    assert any(r["subject"].startswith("FeedItem:") for r in sf)


def test_salesforce_fingerprints_for_origin(client, monkeypatch, db_factory):
    _fake_salesforce(monkeypatch, {
        "Case": [{"Id": "500z", "LastModifiedDate": "2026-08-20T10:00:00.000+0000",
                  "LastModifiedBy": {"Username": "agent@acme.com"}, "Subject": "escalation",
                  "Description": "The enterprise renewal terms and the confidential pricing "
                                 "schedule for globex are attached in the following summary "
                                 "for the account team to review before the call next week."}],
        "FeedItem": [],
    })
    cid = _mk(client, "salesforce_content", SF_CREDS)
    client.post(f"/api/discovery/connectors/{cid}/sync")
    from app.models import ContentFingerprint, Tenant
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    rows = db.query(ContentFingerprint).filter_by(tenant_id=tid, source="salesforce").all()
    assert len(rows) == 1 and rows[0].ref == "Case:500z" and rows[0].shingles
    db.close()


# --- documents, not just plain text ----------------------------------------------------
# Most of a real Drive or document library is uploaded PDFs and Office files. Those used
# to be filtered out before the download and counted as skipped, which meant the library
# most likely to hold a customer export was the one least likely to be read.

import io
import zipfile
import zlib


def _docx_bytes(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="x"><w:body>'
                   f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>")
    return buf.getvalue()


def _pdf_bytes(text: str) -> bytes:
    body = zlib.compress(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode())
    return (b"%PDF-1.4\n1 0 obj<</Length " + str(len(body)).encode() + b">>stream\n"
            + body + b"\nendstream\nendobj\ntrailer<<>>\n%%EOF")


def test_gdrive_reads_an_uploaded_pdf(client, monkeypatch):
    _fake_gdrive(monkeypatch, [
        {"id": "p1", "name": "invoice.pdf", "mimeType": "application/pdf",
         "modifiedTime": "2026-08-20T10:00:00.000Z",
         "lastModifyingUser": {"emailAddress": "alice@acme.com"}},
    ], {"p1": _pdf_bytes("aws key AKIAIOSFODNN7EXAMPLE")})
    cid = _mk(client, "gdrive_files", GDRIVE_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 1 and summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert any("invoice.pdf" in (r.get("subject") or "") for r in rows)


def test_sharepoint_reads_a_word_document(client, monkeypatch):
    _fake_graph(monkeypatch, [
        {"id": "w1", "name": "offer.docx", "size": 900,
         "file": {"mimeType": "application/vnd.openxmlformats-officedocument"
                            ".wordprocessingml.document"},
         "lastModifiedBy": {"user": {"email": "hr@acme.com"}}},
    ], {"w1": _docx_bytes("candidate ssn 412-88-7390")})
    cid = _mk(client, "sharepoint_files", SP_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 1 and summary["findings"] == 1


def test_a_file_nothing_can_open_is_skipped_not_called_clean(client, monkeypatch):
    """Pre-2007 Office is a binary OLE container. It must land in `skipped`, never be
    reported as a scanned file with no findings."""
    _fake_gdrive(monkeypatch, [
        {"id": "d1", "name": "legacy.doc", "mimeType": "application/msword",
         "modifiedTime": "2026-08-20T10:00:00.000Z"},
    ], {"d1": b"\xd0\xcf\x11\xe0binary"})
    cid = _mk(client, "gdrive_files", GDRIVE_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 0 and summary["skipped"] == 1


def test_an_image_is_skipped_while_ocr_is_off(client, monkeypatch):
    import app.ocr as ocr
    monkeypatch.setattr(ocr, "ocr_available", lambda: False)
    _fake_gdrive(monkeypatch, [
        {"id": "i1", "name": "screenshot.png", "mimeType": "image/png",
         "modifiedTime": "2026-08-20T10:00:00.000Z"},
    ], {"i1": b"\x89PNG\r\n\x1a\n"})
    cid = _mk(client, "gdrive_files", GDRIVE_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 0 and summary["skipped"] == 1


def test_an_image_is_read_when_ocr_is_on(client, monkeypatch):
    import app.ocr as ocr
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(ocr, "extract_image_text",
                        lambda imgs, max_images=4, **k: "aws key AKIAIOSFODNN7EXAMPLE")
    _fake_gdrive(monkeypatch, [
        {"id": "i2", "name": "paste.png", "mimeType": "image/png",
         "modifiedTime": "2026-08-20T10:00:00.000Z"},
    ], {"i2": b"\x89PNG\r\n\x1a\n"})
    cid = _mk(client, "gdrive_files", GDRIVE_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 1 and summary["findings"] == 1


# --- Salesforce attachments -----------------------------------------------------------
# Record TEXT was covered; the files attached to those records never were, and a support
# case's attachment is exactly where the customer's own export ends up.

def _fake_salesforce_files(monkeypatch, versions, bodies, records=None):
    records = records or {}
    monkeypatch.setattr(sc, "_salesforce_access",
                        lambda creds: ("https://acme.my.salesforce.com", "tok"))

    def fake_json(url, headers=None, data=None, timeout=20):
        q = urllib.parse.unquote_plus(url.split("q=")[1]) if "q=" in url else ""
        if "FROM ContentVersion" in q:
            return {"records": versions, "done": True}
        for name, recs in records.items():
            if f"FROM {name} " in q:
                return {"records": recs, "done": True}
        return {"records": [], "done": True}

    def fake_bytes(url, headers, cap=sc._MAX_CONTENT_BYTES):
        return bodies[url.split("/ContentVersion/")[1].split("/")[0]]

    monkeypatch.setattr(sc, "_http_json", fake_json)
    monkeypatch.setattr(sc, "_http_bytes", fake_bytes)


def test_salesforce_scans_an_attached_spreadsheet(client, monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/sharedStrings.xml",
                   "<sst><si><t>name</t></si><si><t>ssn</t></si>"
                   "<si><t>Jane Roe</t></si><si><t>412-88-7390</t></si></sst>")
    _fake_salesforce_files(monkeypatch, [
        {"Id": "068x1", "Title": "customers", "FileExtension": "xlsx",
         "ContentSize": 900, "LastModifiedDate": "2026-08-22T10:00:00.000+0000",
         "OwnerId": "005x1"},
    ], {"068x1": buf.getvalue()})
    cid = _mk(client, "salesforce_content", SF_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["files"] == 1 and summary["findings"] == 1
    rows = client.get("/api/findings?surface=collab").json()["findings"]
    assert any("customers.xlsx" in (r.get("subject") or "") for r in rows)


def test_salesforce_unreadable_attachment_is_skipped(client, monkeypatch):
    _fake_salesforce_files(monkeypatch, [
        {"Id": "068x2", "Title": "scan", "FileExtension": "doc", "ContentSize": 900,
         "LastModifiedDate": "2026-08-22T10:00:00.000+0000", "OwnerId": "005x1"},
    ], {"068x2": b"\xd0\xcf\x11\xe0"})
    cid = _mk(client, "salesforce_content", SF_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary.get("files_skipped") == 1 and "files" not in summary


def test_no_contentversion_access_still_scans_records(client, monkeypatch):
    """An org whose profile cannot read ContentVersion must keep its record scan rather
    than losing the whole sync to one permissions error."""
    monkeypatch.setattr(sc, "_salesforce_access",
                        lambda creds: ("https://acme.my.salesforce.com", "tok"))

    def fake_json(url, headers=None, data=None, timeout=20):
        q = urllib.parse.unquote_plus(url.split("q=")[1]) if "q=" in url else ""
        if "FROM ContentVersion" in q:
            raise sc.ConnectorError("HTTP 403 INSUFFICIENT_ACCESS")
        if "FROM Case " in q:
            return {"records": [{"Id": "500x9",
                                 "LastModifiedDate": "2026-08-20T10:00:00.000+0000",
                                 "LastModifiedBy": {"Username": "agent@acme.com"},
                                 "Subject": "leak", "Description": "ssn 412-88-7390"}],
                    "done": True}
        return {"records": [], "done": True}

    monkeypatch.setattr(sc, "_http_json", fake_json)
    cid = _mk(client, "salesforce_content", SF_CREDS)
    summary = client.post(f"/api/discovery/connectors/{cid}/sync").json()
    assert summary["records"] == 1 and summary["findings"] == 1
    assert "files" not in summary
