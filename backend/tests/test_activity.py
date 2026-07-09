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
    _ingest(raw_client, key, "SSN 123-45-6789", "bob@acme.com")

    users = client.get("/api/activity/users").json()["users"]
    by = {u["actor"]: u for u in users}
    assert by["alice@acme.com"]["findings"] == 2
    assert by["alice@acme.com"]["high"] >= 1
    cats = {c["category"] for c in by["alice@acme.com"]["categories"]}
    assert "secret_leak" in cats

    # actor filter on findings returns only that user's items
    only = client.get("/api/findings", params={"actor": "bob@acme.com"}).json()["findings"]
    assert only and all(f["sender"] == "bob@acme.com" for f in only)
