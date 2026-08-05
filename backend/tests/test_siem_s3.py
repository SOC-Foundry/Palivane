"""SIEM S3 delivery sink: severity gating, config gating, event shape, key layout, test endpoint."""

from __future__ import annotations

import app.siem_s3 as s3
import app.service as service


def _capture_puts(monkeypatch):
    calls = []
    monkeypatch.setattr(s3, "_put", lambda *a: (calls.append(a) or (True, "")))
    # dispatch.submit runs in a pool; call synchronously in tests for determinism.
    import app.dispatch as dispatch
    monkeypatch.setattr(dispatch, "submit", lambda fn, *a, **k: fn(*a, **k))
    monkeypatch.setattr(s3, "submit", None, raising=False)
    return calls


def test_key_is_date_partitioned():
    k = s3._key("acme/logs")
    assert k.startswith("acme/logs/warden/findings/") and k.endswith(".json")
    assert s3._key("").startswith("warden/findings/")


def test_forward_gated_by_config_and_severity(monkeypatch):
    calls = _capture_puts(monkeypatch)
    v = {"severity": "critical", "risk_score": 90, "finding_id": 1, "signals": [{"category": "secret_leak"}]}
    # no bucket/creds -> no-op
    s3.forward_s3("", "", "", "", "", "high", v)
    assert calls == []
    # configured + severity >= threshold -> one put, with the shared event shape
    s3.forward_s3("b", "p", "us-east-1", "AKIA_x", "sek", "high", v, subject="s", actor="a", surface="ai_usage", org="acme")
    assert len(calls) == 1
    bucket, prefix, region, kid, sec, fields = calls[0]
    assert bucket == "b" and region == "us-east-1"
    assert fields["product"] == "Palivane" and fields["severity"] == "critical" and fields["org"] == "acme"
    # below threshold -> dropped
    calls.clear()
    s3.forward_s3("b", "p", "us-east-1", "AKIA_x", "sek", "high",
                  {"severity": "low", "risk_score": 5, "signals": []})
    assert calls == []


def test_s3_sink_runs_from_run_analysis(client, raw_client, monkeypatch):
    # Configure the tenant's S3 sink, then an ingest should trigger a put.
    client.patch("/api/tenant", json={"siem_s3_bucket": "palivane-lake", "siem_s3_region": "us-east-1",
                                      "siem_s3_key_id": "AKIAEXAMPLE", "siem_s3_secret": "shh",
                                      "siem_min_severity": "high"})
    calls = _capture_puts(monkeypatch)
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    raw_client.post("/api/ingest/ai-usage",
                    json={"content": "SSN 123-45-6789 key AKIAABCDEFGHIJKLMNOP", "destination": "https://chatgpt.com/"},
                    headers={"X-Palivane-Token": key})
    assert len(calls) >= 1
    assert calls[0][0] == "palivane-lake"


def test_config_is_write_only_in_tenant_dict(client):
    client.patch("/api/tenant", json={"siem_s3_bucket": "b", "siem_s3_key_id": "AKIA", "siem_s3_secret": "sek"})
    t = client.get("/api/auth/me").json()["tenant"]
    assert t["siem_s3_bucket"] == "b" and t["siem_s3_configured"] is True
    assert "siem_s3_secret" not in t and "siem_s3_key_id" not in t   # never returned


def test_s3_test_endpoint(client, monkeypatch):
    monkeypatch.setattr(s3, "_put", lambda *a: (True, ""))
    assert client.post("/api/siem/s3/test").status_code == 400   # nothing configured
    client.patch("/api/tenant", json={"siem_s3_bucket": "b", "siem_s3_key_id": "AKIA", "siem_s3_secret": "sek"})
    r = client.post("/api/siem/s3/test").json()
    assert r["ok"] is True
