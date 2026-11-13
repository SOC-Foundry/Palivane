"""When is each actor usually active? One count per (actor, hour of the week), from the
sensor heartbeats, so a judgement about silence can ask "is this an hour they would
normally be here?" before calling it suspicious.

The first consumer is containment's quiet warning (main._containment_rows): a contained
person who stopped nothing and never checked in looks the same whether they stripped the
hooks or went home for the evening. With this, the warning waits for an hour the person
is usually active (seen in that hour-of-week slot within the last four weeks) and says
nothing about an evening or a weekend they never worked.

Writes are throttled in-process to one per actor per hour, so the capture path pays one
small upsert an hour per person, not one per event. Slots are UTC; a person's working
hours shift with DST twice a year, which the ±1-slot tolerance in `expected_now` absorbs.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import ActorHours

SLOTS = 7 * 24
LOOKBACK = timedelta(days=28)      # a slot counts as "usual" if seen within this
_last_written: dict[tuple[int, str], int] = {}
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def slot_of(t: datetime) -> int:
    return t.weekday() * 24 + t.hour


def _norm(actor: str) -> str:
    return (actor or "").strip().lower()


def note(db: Session, tenant_id: int | None, actor: str, now: datetime | None = None) -> bool:
    """Record that `actor` was active now. Returns True when a row was written (once per
    actor per hour per process; the rest are no-ops). Best-effort: never raises."""
    actor = _norm(actor)
    if tenant_id is None or not actor:
        return False
    now = now or _now()
    slot = slot_of(now)
    key = (tenant_id, actor)
    stamp = now.year * 1_000_000 + now.timetuple().tm_yday * 100 + now.hour
    with _lock:
        if _last_written.get(key) == stamp:
            return False
        _last_written[key] = stamp
    try:
        row = (db.query(ActorHours)
                 .filter(ActorHours.tenant_id == tenant_id, ActorHours.actor == actor,
                         ActorHours.slot == slot).one_or_none())
        if row is None:
            db.add(ActorHours(tenant_id=tenant_id, actor=actor, slot=slot, count=1, last_at=now))
        else:
            row.count = (row.count or 0) + 1
            row.last_at = now
        db.commit()
        return True
    except Exception:
        db.rollback()
        with _lock:
            _last_written.pop(key, None)
        return False


def has_history(db: Session, tenant_id: int, actor: str, now: datetime | None = None) -> bool:
    """Whether anything is known about when this actor is active (within the lookback)."""
    actor = _norm(actor)
    if not actor:
        return False
    now = now or _now()
    return db.query(ActorHours.id).filter(
        ActorHours.tenant_id == tenant_id, ActorHours.actor == actor,
        ActorHours.last_at >= now - LOOKBACK).first() is not None


def expected_now(db: Session, tenant_id: int, actor: str, now: datetime | None = None) -> bool:
    """Whether `actor` is usually active at this hour of the week: seen in this slot, or
    the one either side of it, within the lookback."""
    actor = _norm(actor)
    if not actor:
        return False
    now = now or _now()
    s = slot_of(now)
    slots = [s, (s - 1) % SLOTS, (s + 1) % SLOTS]
    return db.query(ActorHours.id).filter(
        ActorHours.tenant_id == tenant_id, ActorHours.actor == actor,
        ActorHours.slot.in_(slots), ActorHours.last_at >= now - LOOKBACK).first() is not None


# An actor active in this many distinct hours of the day, on this many distinct days of
# the last week, is not keeping a person's hours. A long day is 12 hours; a person on call
# might touch 16; 20 of 24, five days running, is a process.
UNATTENDED_HOURS = 20
UNATTENDED_DAYS = 5


def cadence(db: Session, tenant_id: int, actor: str, now: datetime | None = None) -> dict:
    """How an actor's last week is spread: distinct hours of the day and days seen, and
    whether that is a machine's cadence rather than a person's."""
    actor = _norm(actor)
    now = now or _now()
    rows = (db.query(ActorHours.slot)
              .filter(ActorHours.tenant_id == tenant_id, ActorHours.actor == actor,
                      ActorHours.last_at >= now - timedelta(days=7)).all())
    hours = {slot % 24 for (slot,) in rows}
    days = {slot // 24 for (slot,) in rows}
    return {"hours_of_day": len(hours), "days": len(days),
            "round_the_clock": len(hours) >= UNATTENDED_HOURS and len(days) >= UNATTENDED_DAYS}


def unattended(db: Session, tenant_id: int, now: datetime | None = None) -> list[dict]:
    """Actors on a PERSON's identity (an email) that keep a machine's hours: an unregistered
    agent running under someone's key. Registered agents and non-person actors (a repo, a
    bot's own name) are not candidates. Sorted by hours, most machine-like first."""
    from sqlalchemy import func
    from .models import Agent
    now = now or _now()
    since = now - timedelta(days=7)
    rows = (db.query(ActorHours.actor, func.count(func.distinct(ActorHours.slot % 24)).label("hours"),
                     func.count(func.distinct(ActorHours.slot / 24)).label("days"),
                     func.max(ActorHours.last_at).label("last_at"))
              .filter(ActorHours.tenant_id == tenant_id, ActorHours.last_at >= since,
                      ActorHours.actor.contains("@"))
              .group_by(ActorHours.actor)
              .having(func.count(func.distinct(ActorHours.slot % 24)) >= UNATTENDED_HOURS)
              .all())
    agents = {a.lower() for (a,) in db.query(Agent.name).filter(Agent.tenant_id == tenant_id).all()}
    out = []
    for r in rows:
        # SQLite integer division differs from Postgres for `/`; recount days in Python.
        days = {slot // 24 for (slot,) in db.query(ActorHours.slot).filter(
            ActorHours.tenant_id == tenant_id, ActorHours.actor == r.actor, ActorHours.last_at >= since)}
        # Registered already, under its own name or as the console registers it from
        # the Fleet panel (`agent:<identity>`).
        if len(days) < UNATTENDED_DAYS or r.actor in agents or f"agent:{r.actor}" in agents:
            continue
        out.append({"actor": r.actor, "hours_of_day": int(r.hours), "days": len(days),
                    "last_seen": r.last_at.isoformat() if r.last_at else None})
    out.sort(key=lambda d: (-d["hours_of_day"], -d["days"], d["actor"]))
    return out


def reset_cache() -> None:
    """Tests: forget the per-process write throttle."""
    with _lock:
        _last_written.clear()
