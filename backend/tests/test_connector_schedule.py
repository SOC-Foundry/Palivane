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


def test_a_connector_can_ask_for_its_own_interval(stub, client, db_factory, monkeypatch):
    monkeypatch.setitem(sc.PLATFORMS, "stubfast", {
        "label": "Fast", "scan": sc.PLATFORMS["stubscan"]["scan"], "schedule_secs": 3600,
        "interval_for": lambda creds, default: int(creds.get("every", 0)) * 60 or default,
        "credential_fields": []})
    r = client.post("/api/discovery/connectors", json={"platform": "stubfast", "label": "f",
                                                      "credentials": {"every": 10}})
    assert r.status_code == 200
    now = datetime.utcnow()
    assert _run(db_factory, now) == 1
    assert _run(db_factory, now + timedelta(minutes=5)) == 0
    assert _run(db_factory, now + timedelta(minutes=11)) == 1       # ten minutes, not an hour


def test_an_unreadable_interval_falls_back_to_the_platforms(stub, client, db_factory, monkeypatch):
    def broken(creds, default):
        raise ValueError("bad option")
    monkeypatch.setitem(sc.PLATFORMS, "stubbad", {
        "label": "Bad", "scan": sc.PLATFORMS["stubscan"]["scan"], "schedule_secs": 3600,
        "interval_for": broken, "credential_fields": []})
    client.post("/api/discovery/connectors", json={"platform": "stubbad", "label": "b", "credentials": {}})
    now = datetime.utcnow()
    assert _run(db_factory, now) == 1
    assert _run(db_factory, now + timedelta(minutes=30)) == 0
    assert _run(db_factory, now + timedelta(minutes=61)) == 1


def test_a_scheduled_scan_gets_the_long_clock_and_gives_it_back(stub, db_factory):
    from app import github_secrets as gh
    seen = []
    original = sc.PLATFORMS["stubscan"]["scan"]

    def scan(db, connector, creds):
        seen.append(gh.max_seconds.get())
        return original(db, connector, creds)

    sc.PLATFORMS["stubscan"]["scan"] = scan
    stub["make"]("a")
    _run(db_factory)
    assert seen == [cs.SCAN_MAX_SECS] and gh.max_seconds.get() == 100.0


# --- overlapping scans (#298) ----------------------------------------------------------------------

def _claimed(db_factory, cid):
    db = db_factory()
    try:
        r = db.get(SaasConnector, cid)
        return r.sync_claimed_at, r.state
    finally:
        db.close()


def test_a_scan_still_running_cannot_be_claimed_by_another_instance(stub, db_factory):
    cid = stub["make"]("a")
    t0 = datetime.utcnow() - timedelta(hours=2)
    db1, db2 = db_factory(), db_factory()
    try:
        assert cs._claim(db1, cid, t0, t0) is True                    # scan A starts
        # Six minutes on: past a five-minute interval, still inside a 480s scan. Before #298 the claim
        # was last_sync_at, so this second claim succeeded and both scans wrote the same row.
        later = t0 + timedelta(minutes=6)
        assert cs._claim(db2, cid, later, later) is False
        stale = t0 + timedelta(seconds=sc.SYNC_CLAIM_SECS + 1)        # A died mid-scan: its claim lapses
        assert cs._claim(db2, cid, stale, stale) is True
    finally:
        db1.close()
        db2.close()


def test_last_sync_at_is_when_the_scan_finished_and_the_claim_is_let_go(stub, db_factory):
    cid = stub["make"]("a")
    claimed = datetime.utcnow() - timedelta(hours=2)
    assert _run(db_factory, claimed) == 1
    last, status = _row(db_factory, cid)
    assert status == "ok" and last > claimed + timedelta(hours=1)     # the finish, not the claim
    assert _claimed(db_factory, cid)[0] is None


def test_an_older_scan_cannot_write_its_time_and_cursor_over_a_newer_one(stub, client, db_factory):
    """Scan A outlives its claim; scan B claims the connector and finishes. A's late finish must
    not put its older cursor (or its time) back over B's."""
    cid = stub["make"]("a")
    t0 = datetime.utcnow() - timedelta(hours=3)
    finished = {}

    def scan(db, connector, creds):
        if connector.state.get("who") is None and "B" not in finished:
            # while A runs, its claim lapses and B (another instance) scans the connector start to end
            other = db_factory()
            try:
                b_at = t0 + timedelta(seconds=sc.SYNC_CLAIM_SECS + 60)
                assert sc.claim_sync(other, cid, b_at) is True
                row = other.get(SaasConnector, cid)
                finished["B"] = True
                sc.sync_connector(other, row, claimed_at=b_at)
                finished["B_at"] = other.get(SaasConnector, cid).last_sync_at
            finally:
                other.close()
            connector.state = {"who": "A", "cursor": 1}               # A's older cursor
            return {"files": 1}
        connector.state = {"who": "B", "cursor": 2}
        return {"files": 2}

    sc.PLATFORMS["stubscan"]["scan"] = scan
    db = db_factory()
    try:
        assert sc.claim_sync(db, cid, t0) is True
        row = db.get(SaasConnector, cid)
        sc.sync_connector(db, row, claimed_at=t0)
    finally:
        db.close()
    claim, state = _claimed(db_factory, cid)
    assert state == {"who": "B", "cursor": 2}                         # B's cursor stands
    assert _row(db_factory, cid)[0] == finished["B_at"] and claim is None


def test_scan_now_while_a_scheduled_scan_runs_is_refused_and_reads_nothing(stub, client, db_factory):
    cid = stub["make"]("a")
    db = db_factory()
    try:
        assert sc.claim_sync(db, cid, datetime.utcnow()) is True      # the scheduled scan holds it
    finally:
        db.close()
    r = client.post(f"/api/discovery/connectors/{cid}/sync")
    assert r.status_code == 409 and "already running" in r.text
    assert stub["calls"] == [] and _row(db_factory, cid) == (None, "")


def test_a_rate_limited_scan_is_due_again_when_github_said(stub, db_factory):
    stub["make"]("limited")
    now = datetime.utcnow()
    resume = now + timedelta(minutes=40)
    stub["answer"] = {"truncated": True, "resume_after": resume.strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert _run(db_factory, now) == 1
    assert _run(db_factory, now + timedelta(seconds=cs.CATCH_UP_SECS + 5)) == 0   # not before the reset
    assert _run(db_factory, now + timedelta(minutes=41)) == 1
