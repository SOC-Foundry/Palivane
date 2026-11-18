"""The public status page is the health checks that already exist, and nothing about a tenant."""
from __future__ import annotations

from sqlalchemy.orm import Session


def test_status_is_public_and_carries_no_tenant_data(raw_client):
    r = raw_client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert set(body) <= {"status", "generated_at", "checks"}
    assert body["status"] == "ok"
    assert [c["id"] for c in body["checks"]] == ["api", "database", "judge"]
    assert body["checks"][0]["status"] == "ok"
    assert body["checks"][1]["status"] == "ok"
    blob = r.text.lower()
    for forbidden in ("acme", "admin@", "license", "finding", "signup", "slack", "webhook", "siem"):
        assert forbidden not in blob, forbidden

    page = raw_client.get("/status")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert "Palivane status" in page.text
    assert "<script" not in page.text.lower()
    assert "Operational" in page.text
    lowered = page.text.lower()
    for forbidden in ("acme", "admin@", "license", "signup", "slack"):
        assert forbidden not in lowered, forbidden
    assert "no organization's data" in lowered


def test_status_goes_down_when_the_database_check_fails(raw_client, monkeypatch):
    def boom(self, *a, **k):
        raise RuntimeError("database down")

    monkeypatch.setattr(Session, "execute", boom)
    r = raw_client.get("/api/status")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "down"
    assert body["checks"][1]["id"] == "database" and body["checks"][1]["status"] == "down"
    assert "acme" not in r.text.lower()

    page = raw_client.get("/status")
    assert page.status_code == 503
    assert "Not reachable" in page.text
    assert "<script" not in page.text.lower()


def test_extension_failopen_is_attributed_in_fleet(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    import time
    now = time.time()
    r = raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "hello from the extension", "destination": "https://claude.ai/",
              "user": "ghost@acme.com",
              "scan_failed": {"reasons": {"network": 2}, "first": now - 30, "last": now}},
        headers={"X-Palivane-Token": key, "X-Palivane-Client": "palivane-extension/0.8.0"},
    )
    assert r.status_code == 200, r.text
    fleet = client.get("/api/fleet").json()
    row = next(d for d in fleet["failed_open_devices"] if d["actor"] == "ghost@acme.com")
    assert row["client"] == "palivane-extension"
    assert row["reasons"]["network"] == 2
    assert row["failed_open"] >= 2

    # A hook User-Agent is the client's own claim and wins over the extension header.
    r = raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "hello from the hook", "destination": "https://claude.ai/",
              "user": "hook@acme.com"},
        headers={"X-Palivane-Token": key, "X-Palivane-Client": "palivane-extension/0.8.0",
                 "User-Agent": "palivane-hook/1.2.3"},
    )
    assert r.status_code == 200, r.text
    sensors = client.get("/api/fleet").json()["sensors"]
    hook = next(s for s in sensors if s["actor"] == "hook@acme.com")
    assert hook["client"] == "palivane-hook"
    assert hook["client_version"] == "1.2.3"
