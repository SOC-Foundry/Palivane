"""Recurrence folding (fingerprint dedup) + bulk status triage."""

from __future__ import annotations

from app.models import Finding


def _ingest(raw_client, key, content, user="dev@acme.com"):
    return raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": content, "destination": "https://chatgpt.com/", "user": user},
        headers={"X-Warden-Token": key},
    ).json()


def _key(client):
    return client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]


SECRET_A = "deploy with key AKIAABCDEFGHIJKLMNOP"
PII_B = "customer record: SSN 123-45-6789"


def test_repeat_event_folds_into_one_finding(client, raw_client, db_factory):
    key = _key(client)
    first = _ingest(raw_client, key, SECRET_A)
    second = _ingest(raw_client, key, SECRET_A)
    third = _ingest(raw_client, key, SECRET_A)

    assert first["finding_id"] == second["finding_id"] == third["finding_id"]
    assert third["recurrence"] == 3

    fs = client.get("/api/findings").json()["findings"]
    assert len(fs) == 1
    assert fs[0]["seen_count"] == 3
    assert fs[0]["last_seen"] >= fs[0]["created_at"]


def test_different_signal_type_stays_distinct(client, raw_client):
    key = _key(client)
    a = _ingest(raw_client, key, SECRET_A)
    b = _ingest(raw_client, key, PII_B)  # a different *kind* of leak is a new finding
    assert a["finding_id"] != b["finding_id"]
    assert len(client.get("/api/findings").json()["findings"]) == 2


def test_different_actor_stays_distinct(client, raw_client):
    key = _key(client)
    a = _ingest(raw_client, key, SECRET_A, user="alice@acme.com")
    b = _ingest(raw_client, key, SECRET_A, user="bob@acme.com")
    assert a["finding_id"] != b["finding_id"]


def test_dismissed_recurrence_stays_dismissed(client, raw_client):
    key = _key(client)
    fid = _ingest(raw_client, key, SECRET_A)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})

    again = _ingest(raw_client, key, SECRET_A)
    assert again["finding_id"] == fid
    fs = client.get("/api/findings").json()["findings"]
    assert len(fs) == 1 and fs[0]["status"] == "dismissed" and fs[0]["seen_count"] == 2


def test_bulk_status_scoped_to_tenant(client, raw_client, db_factory):
    key = _key(client)
    ids = [_ingest(raw_client, key, c)["finding_id"] for c in (SECRET_A, PII_B)]
    # a foreign finding must not be touched even if its id is passed
    db = db_factory()
    foreign = Finding(tenant_id=999, severity="high", status="open")
    db.add(foreign); db.commit(); db.refresh(foreign)
    foreign_id = foreign.id
    db.close()

    r = client.post("/api/findings/bulk-status",
                    json={"ids": ids + [foreign_id], "status": "triaged"})
    assert r.status_code == 200 and r.json()["updated"] == 2

    fs = client.get("/api/findings").json()["findings"]
    assert all(f["status"] == "triaged" for f in fs)
    db = db_factory()
    assert db.get(Finding, foreign_id).status == "open"
    db.close()


def test_signals_carry_policy_check_key(client, raw_client):
    key = _key(client)
    _ingest(raw_client, key, SECRET_A)
    f = client.get("/api/findings").json()["findings"][0]
    detail = client.get(f"/api/findings/{f['id']}").json()
    assert all(s.get("check") for s in detail["signals"])
