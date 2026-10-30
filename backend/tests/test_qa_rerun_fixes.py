"""Fixes for problems the QA re-run found (2026-10-30)."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app.main import app

_TOKEN = "q" + "z" * 23


def _siem_url():
    return "https://siem.example.com/collect?token=" + _TOKEN


# --- the SIEM URL's token never comes back -----------------------------------------------

def test_siem_url_is_write_only_everywhere(client):
    r = client.patch("/api/tenant", json={"siem_url": _siem_url()})
    assert r.status_code == 200 and _TOKEN not in r.text
    assert r.json()["siem_url_set"] is True
    assert r.json()["siem_url_host"] == "https://siem.example.com"
    assert _TOKEN not in client.get("/api/auth/me").text
    assert _TOKEN not in client.get("/api/export/tenant").text


def test_an_analyst_cannot_read_the_siem_token(client):
    client.patch("/api/tenant", json={"siem_url": _siem_url()})
    client.post("/api/users", json={"email": "an@acme.com", "password": "analyst-pass-123",
                                    "role": "analyst"})
    raw = TestClient(app)
    tok = raw.post("/api/auth/login", json={"email": "an@acme.com",
                                            "password": "analyst-pass-123"}).json()["access_token"]
    me = raw.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert me.status_code == 200 and _TOKEN not in me.text


def test_clearing_the_siem_url_still_works(client):
    client.patch("/api/tenant", json={"siem_url": _siem_url()})
    r = client.patch("/api/tenant", json={"siem_url": ""}).json()
    assert r["siem_url_set"] is False and r["siem_url_host"] == ""


# --- a streaming request while the provider is down gets the 502 ------------------------------

def test_monitor_stream_with_the_provider_down_is_a_502(client, monkeypatch):
    from app import gateway

    class _Down:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def stream(self, *a, **k):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://api.example", "k"))
    monkeypatch.setattr(gateway, "safe_client", lambda **k: _Down())
    for path, body in (("/v1/messages", {"model": "claude-x", "max_tokens": 8, "stream": True,
                                         "messages": [{"role": "user", "content": "hi"}]}),
                       ("/v1/chat/completions", {"model": "gpt-x", "stream": True,
                                                 "messages": [{"role": "user", "content": "hi"}]})):
        r = client.post(path, json=body)
        assert r.status_code == 502, (path, r.status_code, r.text[:200])
        assert r.json()["error"]["type"] == "upstream_unavailable"


# --- the report counts each analyzed call once ---------------------------------------------

def test_report_does_not_count_agent_calls_twice(client, db_factory):
    from datetime import datetime, timezone

    from app.models import GatewayUsage, Tenant
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").one().id
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for kind, n in (("gateway", 3), ("ag7", 3), ("ingest", 2), ("inference_hook", 1)):
        db.add(GatewayUsage(tenant_id=tid, kind=kind, window_start=now, count=n))
    db.commit(); db.close()
    assert client.get("/api/reports/summary").json()["analyzed_events"] == 6
