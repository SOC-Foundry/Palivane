"""Raw event archival to S3: key layout, config gating, redaction default, NDJSON
batching (size + shutdown flush), daily byte budget, plan gate, and the ingest e2e path."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import app.archive_s3 as a
from app import users as users_cli
from app.config import settings
from app.detectors.base import AnalysisInput
from app.main import app
from app.models import Tenant

SECRETY = "SSN 123-45-6789 key AKIAABCDEFGHIJKLMNOP"


@pytest.fixture
def cap(monkeypatch):
    """Capture batches synchronously and neutralize the background flusher/timers."""
    calls = []
    monkeypatch.setattr(a, "_put_batch",
                        lambda cfg, body, count, tid=0: calls.append((cfg, body, count)))
    monkeypatch.setattr(a, "_submit",
                        lambda cfg, body, count, tid=0: calls.append((cfg, body, count)))
    monkeypatch.setattr(a, "_ensure_flusher", lambda: None)
    monkeypatch.setattr(settings, "archive_flush_secs", 3600)
    a._buffers.clear()
    a._daily.clear()
    for k in a._stats:
        a._stats[k] = 0
    return calls


def _tenant(**kw) -> Tenant:
    base = dict(id=1, slug="acme", siem_s3_bucket="lake", siem_s3_prefix="p",
                siem_s3_region="us-east-1", siem_s3_key_id="AKIA_x", siem_s3_secret="sek",
                siem_naming="palivane", archive_s3_enabled=True)
    base.update(kw)
    return Tenant(**base)


def _item(content: str = SECRETY) -> AnalysisInput:
    return AnalysisInput(content=content, subject="s", sender="e@acme.com", channel="chat")


_RESULT = {"severity": "high", "risk_score": 80, "signals": [{"category": "secret_leak"}]}


def _lines(calls) -> list[dict]:
    return [json.loads(l) for _, body, _ in calls for l in body.decode().strip().split("\n")]


def test_event_key_layout():
    k = a._event_key("acme/logs", "palivane")
    assert k.startswith("acme/logs/palivane/events/") and k.endswith(".ndjson")
    # hour partition: events/YYYY/MM/DD/HH/<uid>.ndjson
    assert len(k.split("/events/")[1].split("/")) == 5
    assert a._event_key("", "warden").startswith("warden/events/")


def test_noop_when_disabled_or_unconfigured(cap):
    a.archive(None, _item(), _RESULT)
    a.archive(_tenant(archive_s3_enabled=False), _item(), _RESULT)
    a.archive(_tenant(siem_s3_secret=""), _item(), _RESULT)   # sink not fully configured
    a.flush_all()
    assert cap == []


def test_batches_and_flushes_ndjson(cap):
    t = _tenant()
    a.archive(t, _item(), _RESULT, agent="copilot")
    a.archive(t, _item("hello"), _RESULT)
    assert cap == []                       # buffered, below the size threshold
    a.flush_all()
    assert len(cap) == 1 and cap[0][2] == 2
    assert cap[0][0] == ("lake", "p", "us-east-1", "AKIA_x", "sek", "palivane")
    ev = _lines(cap)
    assert [e["schema"] for e in ev] == [1, 1]
    assert ev[0]["actor"] == "e@acme.com" and ev[0]["agent"] == "copilot"
    assert ev[0]["severity"] == "high" and ev[0]["surface"] == "llm_io"
    assert ev[0]["signals"][0]["category"] == "secret_leak"
    a.flush_all()
    assert len(cap) == 1                   # buffer drained; nothing left to ship


def test_size_threshold_flushes_immediately(cap, monkeypatch):
    monkeypatch.setattr(settings, "archive_flush_kb", 1)
    a.archive(_tenant(), _item("x" * 2048), _RESULT)
    assert len(cap) == 1                   # crossed 1 KB -> submitted without waiting


def test_content_redacted_by_default_raw_on_optin(cap):
    a.archive(_tenant(), _item(), _RESULT)
    a.flush_all()
    ev = _lines(cap)[0]
    assert ev["content_redacted"] is True
    assert "AKIAABCDEFGHIJKLMNOP" not in ev["content"] and "123-45-6789" not in ev["content"]
    assert "«redacted:" in ev["content"]
    cap.clear()
    a.archive(_tenant(archive_s3_raw_content=True), _item(), _RESULT)
    a.flush_all()
    ev = _lines(cap)[0]
    assert ev["content_redacted"] is False and "AKIAABCDEFGHIJKLMNOP" in ev["content"]


def test_daily_byte_budget(cap, monkeypatch):
    monkeypatch.setattr(settings, "archive_daily_mb", 1)
    t = _tenant()
    assert not a._over_daily_cap(t, t.id, 600 * 1024)
    assert a._over_daily_cap(t, t.id, 600 * 1024)         # would cross 1 MB -> dropped
    t2 = _tenant(id=2, archive_s3_daily_mb=2)             # per-tenant override wins
    assert not a._over_daily_cap(t2, t2.id, 600 * 1024)
    assert not a._over_daily_cap(t2, t2.id, 600 * 1024)
    # archive() drops (and counts) an event that would blow the budget (raw content, so
    # redaction's 20 KB stored-content cap doesn't shrink it under the threshold)
    a.archive(_tenant(id=3, archive_s3_raw_content=True), _item("y" * (2 * 1024 * 1024)), _RESULT)
    assert a._stats["dropped_cap"] == 1 and a._buffers == {}


def test_plan_gated_enable_free_disable(db_factory):
    db = db_factory()
    users_cli.create_tenant(db, "freeco", "Freeco", plan="free")
    users_cli.create_user(db, "freeco", "admin@freeco.com", "password123", "admin")
    db.close()
    c = TestClient(app)
    tok = c.post("/api/auth/login",
                 json={"email": "admin@freeco.com", "password": "password123"}).json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {tok}"})
    assert c.patch("/api/tenant", json={"archive_s3_enabled": True}).status_code == 402
    assert c.patch("/api/tenant", json={"archive_s3_enabled": False}).status_code == 200


def test_ingest_e2e_and_settings_roundtrip(client, raw_client, cap):
    r = client.patch("/api/tenant", json={
        "siem_s3_bucket": "palivane-lake", "siem_s3_region": "us-east-1",
        "siem_s3_key_id": "AKIAEXAMPLE", "siem_s3_secret": "shh",
        "archive_s3_enabled": True, "archive_s3_daily_mb": 5})
    assert r.status_code == 200
    me = client.get("/api/auth/me").json()["tenant"]
    assert me["archive_s3_enabled"] is True and me["archive_s3_raw_content"] is False
    assert me["archive_s3_daily_mb"] == 5
    assert "siem_s3_secret" not in me                      # creds stay write-only
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    raw_client.post("/api/ingest/ai-usage",
                    json={"content": SECRETY, "destination": "https://chatgpt.com/"},
                    headers={"X-Palivane-Token": key})
    a.flush_all()
    ev = _lines(cap)
    assert len(ev) >= 1 and ev[0]["org"] == "acme"
    assert cap[0][0][0] == "palivane-lake"
    assert ev[0]["content_redacted"] is True and "AKIAEXAMPLE" not in ev[0]["content"]


def test_archive_test_endpoint(client, monkeypatch):
    keys = []
    monkeypatch.setattr(a, "_client", lambda *args: type(
        "S3", (), {"put_object": lambda self, **kw: keys.append(kw["Key"])})())
    assert client.post("/api/siem/s3/archive/test").status_code == 400   # nothing configured
    client.patch("/api/tenant", json={"siem_s3_bucket": "b", "siem_s3_key_id": "AKIA",
                                      "siem_s3_secret": "sek"})
    r = client.post("/api/siem/s3/archive/test").json()
    assert r["ok"] is True
    assert "/events/" in keys[0] or keys[0].startswith("palivane/events/")
