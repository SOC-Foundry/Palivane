"""Containment's quiet warning waits for an hour the target is usually active. A person
contained at six and gone home for the evening looked exactly like one who stripped the
hooks; now the warning asks the actor-hours history first, and a target with no history
keeps the plain one-hour rule."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import activity
from app.models import ActorHours, Containment, SensorHeartbeat, Tenant

_UA = "palivane-hook/1.1.0 (claude-code/2.1.4)"


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


def _seen(db_factory, tid, actor, at):
    """`actor` was active at `at`: an actor-hours slot, as the heartbeat path writes it."""
    db = db_factory()
    activity.note(db, tid, actor, at)
    db.close()


def _contain(client, target, scope="user", hours_ago=2.0):
    r = client.post("/api/containments", json={"scope": scope, "target": target, "hours": 24})
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    return cid


def _backdate(db_factory, cid, hours_ago):
    db = db_factory()
    c = db.get(Containment, cid)
    c.created_at = _now() - timedelta(hours=hours_ago)
    db.commit()
    db.close()


def _row(client, cid):
    return next(c for c in client.get("/api/containments").json()["containments"] if c["id"] == cid)


# --- the history -------------------------------------------------------------------------------

def test_a_heartbeat_notes_the_hour_once_per_actor_per_hour(client, raw_client, db_factory):
    tid = _tid(db_factory)
    key = client.post("/api/apikeys", json={"label": "hook", "actor": "dev@acme.com"}).json()["token"]
    for _ in range(3):
        r = raw_client.post("/api/ingest/mcp",
                            json={"method": "tools/call", "tool": "Bash", "transport": "stdio",
                                  "parse_miss": True, "user": "dev@acme.com"},
                            headers={"X-Palivane-Token": key, "User-Agent": _UA})
        assert r.status_code == 200
    db = db_factory()
    rows = db.query(ActorHours).filter(ActorHours.tenant_id == tid).all()
    assert [(r.actor, r.slot, r.count) for r in rows] == [("dev@acme.com", activity.slot_of(_now()), 1)]
    db.close()


def test_expected_now_reads_the_same_weekday_and_hour_within_four_weeks(client, db_factory):
    tid = _tid(db_factory)
    now = _now()
    _seen(db_factory, tid, "Dev@acme.com", now - timedelta(days=7))        # same slot, last week
    db = db_factory()
    assert activity.has_history(db, tid, "dev@acme.com", now)
    assert activity.expected_now(db, tid, "dev@acme.com", now)
    assert activity.expected_now(db, tid, "dev@acme.com", now + timedelta(hours=1))   # ±1 slot
    assert not activity.expected_now(db, tid, "dev@acme.com", now + timedelta(hours=5))
    assert not activity.expected_now(db, tid, "dev@acme.com", now + timedelta(days=1))
    db.close()
    # Seen only five weeks ago: too old to say anything.
    activity.reset_cache()
    _seen(db_factory, tid, "old@acme.com", now - timedelta(days=35))
    db = db_factory()
    assert not activity.has_history(db, tid, "old@acme.com", now)
    db.close()


# --- the warning ---------------------------------------------------------------------------------

def test_silence_at_an_unusual_hour_is_not_quiet(client, db_factory):
    tid = _tid(db_factory)
    now = _now()
    # Usually active ten hours from now (and never at this hour).
    _seen(db_factory, tid, "dev@acme.com", now + timedelta(hours=10) - timedelta(days=7))
    cid = _contain(client, "dev@acme.com")
    _backdate(db_factory, cid, 2)
    assert _row(client, cid)["quiet"] is False


def test_silence_at_a_usual_hour_is_quiet(client, db_factory):
    tid = _tid(db_factory)
    now = _now()
    _seen(db_factory, tid, "dev@acme.com", now - timedelta(days=7))
    cid = _contain(client, "dev@acme.com")
    _backdate(db_factory, cid, 2)
    assert _row(client, cid)["quiet"] is True


def test_a_target_with_no_history_keeps_the_one_hour_rule(client, db_factory):
    cid = _contain(client, "new@acme.com")
    assert _row(client, cid)["quiet"] is False          # under an hour
    _backdate(db_factory, cid, 2)
    assert _row(client, cid)["quiet"] is True


def test_a_check_in_since_containment_is_never_quiet(client, db_factory):
    tid = _tid(db_factory)
    now = _now()
    _seen(db_factory, tid, "dev@acme.com", now - timedelta(days=7))
    cid = _contain(client, "dev@acme.com")
    _backdate(db_factory, cid, 2)
    db = db_factory()
    db.add(SensorHeartbeat(tenant_id=tid, actor="dev@acme.com", plane="ai-usage", tool="claude-code",
                           client="palivane-hook", first_seen=now, last_seen=now, count=1))
    db.commit()
    db.close()
    assert _row(client, cid)["quiet"] is False


def test_an_agents_history_is_its_own(client, db_factory):
    tid = _tid(db_factory)
    now = _now()
    r = client.post("/api/agents", json={"name": "release-bot"})
    assert r.status_code == 200, r.text
    _seen(db_factory, tid, "release-bot", now + timedelta(hours=8) - timedelta(days=14))
    cid = _contain(client, "release-bot", scope="agent")
    _backdate(db_factory, cid, 3)
    assert _row(client, cid)["quiet"] is False          # a nightly bot, contained in the day
