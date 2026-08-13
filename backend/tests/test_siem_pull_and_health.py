"""SIEM pull integration (API-key export auth + since watermark), sink delivery health,
and at-rest sealing of SIEM credentials."""

from __future__ import annotations

import json

from app import siem, sink_health
from app.crypto import unseal
from app.models import Tenant


def _mint_key(client, label="siem-poller"):
    r = client.post("/api/apikeys", json={"label": label, "actor": "siem@acme.com"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _persist_finding(client):
    r = client.post("/api/analyze", json={
        "content": "URGENT verify your account and confirm your password", "persist": True})
    assert r.status_code == 200, r.text
    return r.json()["finding_id"]


# --- fix 1: machine pull ---------------------------------------------------------------

def test_api_key_can_pull_findings_export(client, raw_client):
    _persist_finding(client)
    key = _mint_key(client)
    # Authorization: Bearer ak_… (what a SIEM poller would send)
    r = raw_client.get("/api/export/findings", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    assert len([l for l in r.text.splitlines() if l.strip()]) == 1
    # X-Palivane-Token also works (same header the sensors use)
    r2 = raw_client.get("/api/export/findings", headers={"X-Palivane-Token": key})
    assert r2.status_code == 200


def test_export_rejects_bad_key_and_non_admin_session(client, raw_client, db_factory):
    assert raw_client.get("/api/export/findings",
                          headers={"Authorization": "Bearer ak_bogusbogusbogus"}).status_code == 401
    assert raw_client.get("/api/export/findings").status_code == 401
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    at = client.post("/api/auth/login", json={"email": "analyst@acme.com",
                                              "password": "password123"}).json()["access_token"]
    r = raw_client.get("/api/export/findings", headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 403                     # session path still requires admin


def test_since_watermark_incremental_pull(client, raw_client):
    _persist_finding(client)
    key = _mint_key(client)
    h = {"Authorization": f"Bearer {key}"}
    # Watermark in the past: the finding is returned, with the next watermark advertised.
    r = raw_client.get("/api/export/findings?since=2000-01-01T00:00:00Z", headers=h)
    assert r.status_code == 200
    rows = [json.loads(l) for l in r.text.splitlines() if l.strip()]
    assert len(rows) == 1
    nxt = r.headers.get("X-Palivane-Next-Since")
    assert nxt
    # The filter is inclusive: re-polling AT the watermark re-sends the boundary row
    # (at-least-once — consumers dedupe on finding_id) instead of skipping ties.
    r2 = raw_client.get(f"/api/export/findings?since={nxt}", headers=h)
    assert len([l for l in r2.text.splitlines() if l.strip()]) == 1
    # A future watermark yields an empty window and no next watermark.
    r3 = raw_client.get("/api/export/findings?since=2100-01-01T00:00:00Z", headers=h)
    assert r3.text.strip() == "" and "X-Palivane-Next-Since" not in r3.headers
    # Garbage watermark -> 400, not a silent full dump.
    assert raw_client.get("/api/export/findings?since=yesterdayish", headers=h).status_code == 400


def test_audit_export_accepts_api_key_and_since(client, raw_client):
    key = _mint_key(client)
    h = {"Authorization": f"Bearer {key}"}
    r = raw_client.get("/api/audit/export?since=2000-01-01T00:00:00Z", headers=h)
    assert r.status_code == 200
    assert raw_client.get("/api/audit/export?since=nope", headers=h).status_code == 400
    assert raw_client.get("/api/audit/export").status_code == 401


def test_tenant_export_stays_session_admin_only(client, raw_client):
    # The full-org export (config, users, SSO setup) is deliberately NOT reachable with
    # an ingest API key — only a console admin session.
    key = _mint_key(client)
    r = raw_client.get("/api/export/tenant", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 401
    assert client.get("/api/export/tenant").status_code == 200


# --- fix 2: delivery visibility --------------------------------------------------------

def test_sink_health_records_and_snapshots():
    sink_health.reset()
    sink_health.record(1, "siem_http", True)
    sink_health.record(1, "siem_http", False, "HTTP Error 401: Unauthorized")
    s = sink_health.snapshot(1)["siem_http"]
    assert s["attempted"] and s["ok"] == 1 and s["failed"] == 1
    assert "401" in s["last_error"] and s["last_error_at"]
    # other tenants see nothing
    assert sink_health.snapshot(2)["siem_http"]["attempted"] is False


def test_forward_failure_lands_in_sink_health(monkeypatch):
    sink_health.reset()
    import app.dispatch as dispatch
    monkeypatch.setattr(dispatch, "submit", lambda fn, *a, **k: fn(*a, **k))
    monkeypatch.setattr(siem, "send_detail", lambda *a, **k: (False, "HTTP Error 403: token expired"))
    siem.forward("https://c/x", "tok", "high", "json",
                 {"severity": "critical", "risk_score": 90, "signals": []}, tenant_id=42)
    s = sink_health.snapshot(42)["siem_http"]
    assert s["failed"] == 1 and "403" in s["last_error"]


def test_siem_status_endpoint(client, raw_client):
    r = client.get("/api/siem/status")
    assert r.status_code == 200
    body = r.json()
    assert set(body["sinks"]) == {"siem_http", "siem_s3", "archive_s3"}
    assert "batches" in body["archive"] and "put_failures" in body["archive"]
    assert raw_client.get("/api/siem/status").status_code == 401


def test_siem_test_endpoint_returns_detail(client, monkeypatch):
    client.patch("/api/tenant", json={"siem_url": "https://collector.acme.com/in",
                                      "siem_token": "sekret"})
    monkeypatch.setattr(siem, "send_detail",
                        lambda *a, **k: (False, "HTTP Error 401: Unauthorized"))
    r = client.post("/api/siem/test").json()
    assert r["ok"] is False and "401" in r["detail"]   # not a bare boolean anymore


# --- fix 3: credentials sealed at rest --------------------------------------------------

def test_siem_credentials_sealed_at_rest(client, db_factory):
    client.patch("/api/tenant", json={"siem_url": "https://collector.acme.com/in",
                                      "siem_token": "hec-token-123",
                                      "siem_s3_bucket": "lake", "siem_s3_key_id": "AKIA",
                                      "siem_s3_secret": "aws-secret-456"})
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    assert t.siem_token.startswith("enc:v1:") and "hec-token-123" not in t.siem_token
    assert t.siem_s3_secret.startswith("enc:v1:") and "aws-secret-456" not in t.siem_s3_secret
    assert unseal(t.siem_token) == "hec-token-123"
    assert unseal(t.siem_s3_secret) == "aws-secret-456"
    db.close()


def test_legacy_plaintext_credentials_still_work(client, db_factory, monkeypatch):
    # A pre-sealing row (plaintext credential) must keep flowing to the sink unchanged.
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    t.siem_url, t.siem_token = "https://collector.acme.com/in", "legacy-plain-token"
    db.commit()
    db.close()
    seen = {}
    monkeypatch.setattr(siem, "send_detail",
                        lambda url, token, *a, **k: (seen.update(token=token) or True, ""))
    r = client.post("/api/siem/test").json()
    assert r["ok"] is True
    assert seen["token"] == "legacy-plain-token"      # unseal passes plaintext through


def test_sealed_token_unsealed_at_send_time(client, monkeypatch):
    client.patch("/api/tenant", json={"siem_url": "https://collector.acme.com/in",
                                      "siem_token": "fresh-sealed-token"})
    seen = {}
    monkeypatch.setattr(siem, "send_detail",
                        lambda url, token, *a, **k: (seen.update(token=token) or True, ""))
    client.post("/api/siem/test")
    assert seen["token"] == "fresh-sealed-token"      # the wire sees plaintext, not enc:v1:
