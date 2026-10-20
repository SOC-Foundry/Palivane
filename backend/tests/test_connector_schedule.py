"""Scheduled connector scans: who is due, who claims it, and how a big first pass catches up."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app import connector_schedule as cs
from app import saas_connectors as sc
from app.models import SaasConnector


@pytest.fixture
def stub(client, monkeypatch):
    """A scheduled platform whose scan just counts its calls (and can be told what to answer)."""
    box = {"calls": [], "answer": {"files": 0}, "raise": None}

    def scan(db, connector, creds):
        box["calls"].append(connector.label)
        if box["raise"]:
            raise box["raise"]
        return dict(box["answer"])

    monkeypatch.setitem(sc.PLATFORMS, "stubscan", {"label": "Stub", "scan": scan, "schedule_secs": 3600,
                                                    "credential_fields": []})
    monkeypatch.setitem(sc.PLATFORMS, "stubmanual", {"label": "Manual", "scan": scan,
                                                      "credential_fields": []})

    def make(label, platform="stubscan"):
        r = client.post("/api/discovery/connectors", json={"platform": platform, "label": label,
                                                          "credentials": {}})
        assert r.status_code == 200, r.text
        return r.json()["id"]

    box["make"] = make
    return box


def _run(db_factory, now=None, **kw):
    db = db_factory()
    try:
        return cs.run_scheduled_scans(db, now=now, **kw)
    finally:
        db.close()


def _row(db_factory, cid):
    db = db_factory()
    try:
        r = db.get(SaasConnector, cid)
        return r.last_sync_at, r.last_sync_status
    finally:
        db.close()


def test_a_due_connector_is_scanned_once_per_interval(stub, db_factory):
    stub["make"]("a")
    now = datetime.utcnow()
    assert _run(db_factory, now) == 1
    assert _run(db_factory, now + timedelta(minutes=10)) == 0          # not due yet
    assert _run(db_factory, now + timedelta(minutes=61)) == 1          # an interval later
    assert stub["calls"] == ["a", "a"]


def test_a_platform_without_a_schedule_is_never_scanned_on_its_own(stub, db_factory):
    stub["make"]("m", platform="stubmanual")
    assert _run(db_factory) == 0 and stub["calls"] == []


def test_an_inactive_connector_is_left_alone(stub, client, db_factory):
    cid = stub["make"]("a")
    db = db_factory()
    db.query(SaasConnector).filter_by(id=cid).update({"active": False})
    db.commit()
    db.close()
    assert _run(db_factory) == 0


def test_only_one_instance_wins_the_claim(stub, db_factory):
    cid = stub["make"]("a")
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=1)
    db1, db2 = db_factory(), db_factory()
    try:
        assert cs._claim(db1, cid, now, cutoff) is True
        assert cs._claim(db2, cid, now, cutoff) is False               # the second sees it already claimed
    finally:
        db1.close()
        db2.close()


def test_a_scan_that_ran_out_of_budget_is_due_again_soon(stub, db_factory):
    stub["make"]("big")
    stub["answer"] = {"files": 400, "truncated": True}
    now = datetime.utcnow()
    assert _run(db_factory, now) == 1
    assert _run(db_factory, now + timedelta(minutes=2)) == 0
    assert _run(db_factory, now + timedelta(seconds=cs.CATCH_UP_SECS + 5)) == 1   # catches up, not an hour later


def test_a_clean_scan_waits_its_interval(stub, db_factory):
    stub["make"]("done")
    stub["answer"] = {"files": 10}
    now = datetime.utcnow()
    _run(db_factory, now)
    assert _run(db_factory, now + timedelta(seconds=cs.CATCH_UP_SECS + 5)) == 0


def test_a_failing_connector_does_not_stop_the_others(stub, db_factory):
    bad, good = stub["make"]("bad"), stub["make"]("good")
    calls = stub["calls"]

    original = sc.PLATFORMS["stubscan"]["scan"]

    def scan(db, connector, creds):
        if connector.label == "bad":
            raise sc.ConnectorError("HTTP 401: bad credentials")
        return original(db, connector, creds)

    sc.PLATFORMS["stubscan"]["scan"] = scan
    assert _run(db_factory) == 2
    assert calls == ["good"]
    assert _row(db_factory, bad)[1] == "error"          # recorded for the admin, tried again next interval
    assert _row(db_factory, good)[1] == "ok"


def test_an_unexpected_error_is_contained(stub, db_factory):
    stub["make"]("a")
    stub["raise"] = RuntimeError("boom")
    assert _run(db_factory) == 1                         # counted, logged, not raised


def test_a_tick_scans_at_most_a_few_connectors(stub, db_factory):
    for i in range(5):
        stub["make"](f"c{i}")
    assert _run(db_factory, limit=3) == 3
    assert _run(db_factory, limit=3) == 2                # the rest on the next tick


def test_the_switch_turns_it_off(stub, db_factory, monkeypatch):
    stub["make"]("a")
    monkeypatch.setattr(cs.settings, "connector_schedule", False)
    assert _run(db_factory) == 0 and stub["calls"] == []


def test_github_secret_scanning_is_scheduled_hourly():
    assert sc.PLATFORMS["github_secrets"]["schedule_secs"] == 3600
    assert not any(v.get("schedule_secs") for k, v in sc.PLATFORMS.items() if k != "github_secrets")
