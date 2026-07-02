"""Per-tenant gateway rate limiting + usage metering."""

from __future__ import annotations

from app import gateway

BENIGN = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Summarize this report."}]}


def test_unlimited_by_default(client, monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_rate_limit", 0)   # global default: off
    for _ in range(5):
        assert client.post("/v1/chat/completions", json=BENIGN).status_code == 200


def test_per_tenant_rate_limit_enforced(client, monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    client.patch("/api/tenant", json={"rate_limit": 2})   # 2 requests/min for this org
    assert client.post("/v1/chat/completions", json=BENIGN).status_code == 200
    assert client.post("/v1/chat/completions", json=BENIGN).status_code == 200
    r = client.post("/v1/chat/completions", json=BENIGN)
    assert r.status_code == 429
    assert r.headers.get("retry-after") == "60"
    assert r.json()["error"]["type"] == "rate_limited"


def test_rate_limit_negative_rejected(client):
    assert client.patch("/api/tenant", json={"rate_limit": -1}).status_code == 400


def test_usage_endpoint_reports_counts(client, monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    client.patch("/api/tenant", json={"rate_limit": 100})
    for _ in range(3):
        client.post("/v1/chat/completions", json=BENIGN)
    u = client.get("/api/usage").json()
    assert u["limit_per_min"] == 100
    assert u["current_window"] >= 3 and u["last_24h"] >= 3
    assert sum(u["by_day"].values()) >= 3


def test_global_default_limit_applies_without_tenant_override(client, monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_rate_limit", 1)   # global 1/min, no tenant override
    assert client.post("/v1/chat/completions", json=BENIGN).status_code == 200
    assert client.post("/v1/chat/completions", json=BENIGN).status_code == 429


def test_ingest_shares_the_tenant_rate_limit(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "i", "actor": "x"}).json()["token"]
    client.patch("/api/tenant", json={"rate_limit": 1})
    body = {"content": "hello there", "destination": "https://chat.openai.com/"}
    h = {"X-Warden-Token": key}
    r1 = raw_client.post("/api/ingest/ai-usage", json=body, headers=h)
    r2 = raw_client.post("/api/ingest/ai-usage", json=body, headers=h)
    assert r1.status_code == 200 and r2.status_code == 429
    assert r2.headers.get("retry-after") == "60"


def test_scan_code_is_rate_limited(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "g", "actor": "ci"}).json()["token"]
    client.patch("/api/tenant", json={"rate_limit": 1})
    body = {"files": [{"path": "a.py", "content": "print(1)"}]}
    h = {"X-Warden-Token": key}
    assert raw_client.post("/api/scan/code", json=body, headers=h).status_code == 200
    assert raw_client.post("/api/scan/code", json=body, headers=h).status_code == 429