"""Per-user scan-log aggregate + actor filter on findings."""

from __future__ import annotations


def _ingest(raw_client, key, content, user):
    return raw_client.post("/api/ingest/ai-usage",
                           json={"content": content, "destination": "https://chatgpt.com/", "user": user},
                           headers={"X-Warden-Token": key})


def test_activity_users_aggregates_by_actor(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    _ingest(raw_client, key, "SSN 123-45-6789 key AKIAABCDEFGHIJKLMNOP", "alice@acme.com")
    _ingest(raw_client, key, "just a benign question about weather", "alice@acme.com")
    _ingest(raw_client, key, "card 4111 1111 1111 1111", "alice@acme.com")
    _ingest(raw_client, key, "SSN 123-45-6789", "bob@acme.com")

    users = client.get("/api/activity/users").json()["users"]
    by = {u["actor"]: u for u in users}
    # 2 risky captures became findings; the benign one was dropped (not persisted).
    assert by["alice@acme.com"]["findings"] == 2
    assert by["alice@acme.com"]["high"] >= 1
    cats = {c["category"] for c in by["alice@acme.com"]["categories"]}
    assert "secret_leak" in cats

    # actor filter on findings returns only that user's items
    only = client.get("/api/findings", params={"actor": "bob@acme.com"}).json()["findings"]
    assert only and all(f["sender"] == "bob@acme.com" for f in only)


def test_stats_analyzed_total_counts_traffic_not_findings(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    _ingest(raw_client, key, "benign question one", "alice@acme.com")
    _ingest(raw_client, key, "benign question two", "alice@acme.com")
    _ingest(raw_client, key, "SSN 123-45-6789", "alice@acme.com")

    s = client.get("/api/stats").json()
    assert s["total"] == 1           # only the risky capture became a finding
    assert s["analyzed_total"] == 3  # but every metered request counts as analyzed traffic
