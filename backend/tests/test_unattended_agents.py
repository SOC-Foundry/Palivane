"""A person's identity keeping a machine's hours is an agent nobody registered: a cron'd
coding agent or a CI job under someone's key. Found from the actor-hours history, listed on
Fleet, registered as an agent in one click."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import activity
from app.models import Tenant


@pytest.fixture(autouse=True)
def _fresh():
    activity.reset_cache()
    yield
    activity.reset_cache()


def _tid(db_factory):
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == "acme").one().id
    finally:
        db.close()


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _active(db_factory, tid, actor, days, hours):
    """`actor` seen at each of `hours` on each of the last `days` days."""
    db = db_factory()
    now = _now()
    for d in range(days):
        for h in hours:
            activity.note(db, tid, actor, (now - timedelta(days=d)).replace(hour=h, minute=5))
    db.close()


def test_a_person_keeps_a_persons_hours(client, db_factory):
    tid = _tid(db_factory)
    _active(db_factory, tid, "dev@acme.com", days=5, hours=range(9, 18))      # nine to five
    db = db_factory()
    c = activity.cadence(db, tid, "dev@acme.com")
    assert c == {"hours_of_day": 9, "days": 5, "round_the_clock": False}
    assert activity.unattended(db, tid) == []
    db.close()


def test_a_machine_under_a_persons_key_is_listed(client, db_factory):
    tid = _tid(db_factory)
    _active(db_factory, tid, "ci-runner@acme.com", days=6, hours=range(0, 24, 1))
    _active(db_factory, tid, "dev@acme.com", days=5, hours=range(9, 18))
    db = db_factory()
    assert activity.cadence(db, tid, "ci-runner@acme.com")["round_the_clock"] is True
    db.close()
    r = client.get("/api/fleet/unattended")
    assert r.status_code == 200, r.text
    rows = r.json()["unattended"]
    assert [x["actor"] for x in rows] == ["ci-runner@acme.com"]
    assert rows[0]["hours_of_day"] == 24 and rows[0]["days"] == 6 and rows[0]["last_seen"]
    assert r.json()["limits"] == {"hours": 20, "days": 5}


def test_a_short_burst_is_not_a_machine(client, db_factory):
    tid = _tid(db_factory)
    _active(db_factory, tid, "dev@acme.com", days=2, hours=range(0, 24))      # an all-nighter, twice
    db = db_factory()
    assert activity.cadence(db, tid, "dev@acme.com")["round_the_clock"] is False
    assert activity.unattended(db, tid) == []
    db.close()


def test_a_registered_agent_and_a_non_person_are_not_candidates(client, db_factory):
    tid = _tid(db_factory)
    _active(db_factory, tid, "bot@acme.com", days=7, hours=range(0, 24))
    _active(db_factory, tid, "northgate/billing", days=7, hours=range(0, 24))   # a CI repo
    assert client.post("/api/agents", json={"name": "bot@acme.com"}).status_code == 200
    db = db_factory()
    assert activity.unattended(db, tid) == []
    db.close()


def test_the_people_ledger_flags_the_cadence(client, db_factory):
    tid = _tid(db_factory)
    from app.models import SensorHeartbeat
    _active(db_factory, tid, "ci-runner@acme.com", days=6, hours=range(0, 24))
    db = db_factory()
    now = _now()
    for actor in ("ci-runner@acme.com", "dev@acme.com"):
        db.add(SensorHeartbeat(tenant_id=tid, actor=actor, plane="mcp", tool="", client="palivane-hook",
                               first_seen=now, last_seen=now, count=1))
    db.commit()
    db.close()
    people = {p["actor"]: p for p in client.get("/api/fleet/people?attention=0").json()["people"]}
    assert people["ci-runner@acme.com"]["round_the_clock"] is True
    assert people["dev@acme.com"]["round_the_clock"] is False


def test_registering_from_the_panel_makes_it_an_agent(client, db_factory):
    tid = _tid(db_factory)
    _active(db_factory, tid, "ci-runner@acme.com", days=6, hours=range(0, 24))
    r = client.post("/api/agents", json={"name": "agent:ci-runner@acme.com", "kind": "service"})
    assert r.status_code == 200 and r.json()["token"].startswith("ag_")
    assert client.get("/api/fleet/unattended").json()["unattended"] == []     # registered: off the list
