"""Containment: an admin's "stop this now" on a person, a device, an agent or the whole org.

While a containment is active, every capture decision for its target answers block (the
browser extension, the coding-agent hooks, the MCP and agent-to-agent planes) and the gateway
refuses its model calls. The answer is a normal 200 verdict, not an HTTP error: the hooks treat
a 401/403 as a revoked key and stand down, which here would mean failing open, the opposite of
the point. The verdict carries `force_block` (blocked even in monitor mode), `enforce` (the
hooks switch tool calls to inline checks) and `contained` (until when, and what to tell the
person), which the clients remember so a contained device fails CLOSED while it cannot reach
Palivane, instead of the usual fail-open (see `contained_note` in the hooks).

Scopes, checked in this order:
  org     everything in the tenant ("*")
  agent   a registered agent, by name
  device  one enrollment key (one machine), by key id
  user    a person, by email, on every device and key that attributes to them

A containment always ends: at `expires_at` (default 24 hours, at most 30 days), or earlier when
someone releases it. Rows are kept as the record. The reason is for the security team and is not
shown to the person; they are told they were paused, until when, and to contact security.

Lookups run on every capture decision, so active containments are cached per tenant for a few
seconds (an empty list is the common case and costs nothing); this process's cache is dropped on
create and release, other instances catch up within the TTL.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

SCOPES = ("org", "agent", "device", "user")
DEFAULT_HOURS = 24
MAX_HOURS = 24 * 30
_TTL = 5.0

_cache: dict[int, tuple[float, list[dict]]] = {}
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _epoch(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def invalidate(tenant_id: int | None = None) -> None:
    with _lock:
        if tenant_id is None:
            _cache.clear()
        else:
            _cache.pop(tenant_id, None)


def active(db, tenant_id: int | None) -> list[dict]:
    """This tenant's active containments, as plain dicts (cached for a few seconds)."""
    if not tenant_id:
        return []
    now_mono = time.monotonic()
    with _lock:
        hit = _cache.get(tenant_id)
        if hit and now_mono - hit[0] < _TTL:
            return hit[1]
    from .models import Containment
    now = _now()
    rows = (db.query(Containment)
              .filter(Containment.tenant_id == tenant_id, Containment.released_at.is_(None),
                      Containment.expires_at > now)
              .all())
    out = [{"id": r.id, "scope": r.scope, "target": r.target, "expires_at": r.expires_at}
           for r in rows]
    with _lock:
        _cache[tenant_id] = (now_mono, out)
    return out


def _key_id(db, token: str) -> int:
    from .models import ApiKey
    from .security import hash_token, looks_like_api_key
    if not looks_like_api_key(token or ""):
        return 0
    row = db.query(ApiKey.id).filter(ApiKey.token_hash == hash_token(token)).first()
    return int(row[0]) if row else 0


def match(db, tenant_id: int | None, actor: str = "", agent: str = "",
          token: str = "", key_id: int = 0) -> dict | None:
    """The active containment that covers this caller, or None. The device is `key_id` when
    the caller already resolved it (the gateway), else looked up from the capture credential
    `token`, and only when some device is contained."""
    rows = active(db, tenant_id)
    if not rows:
        return None
    by_scope: dict[str, list[dict]] = {}
    for r in rows:
        by_scope.setdefault(r["scope"], []).append(r)
    if by_scope.get("org"):
        return by_scope["org"][0]
    if agent:
        for r in by_scope.get("agent", ()):
            if r["target"] == agent:
                return r
    if by_scope.get("device"):
        kid = key_id or _key_id(db, token)
        if kid:
            for r in by_scope["device"]:
                if r["target"] == str(kid):
                    return r
    who = (actor or "").strip().lower()
    if who:
        for r in by_scope.get("user", ()):
            if r["target"] == who:
                return r
    return None


def message(c: dict) -> str:
    """What the person is told. Not the reason: that is the security team's."""
    until = c["expires_at"].strftime("%Y-%m-%d %H:%M UTC")
    return (f"Paused by your security team. AI tools and agents are stopped for this "
            f"{'organization' if c['scope'] == 'org' else 'account' if c['scope'] == 'user' else c['scope']} "
            f"until {until}, or until security releases it. Contact your security team.")


def verdict(c: dict) -> dict:
    """The capture answer while contained: a block every client enforces, in any mode."""
    msg = message(c)
    return {"action": "block", "force_block": True, "enforce": True, "risk_score": 100,
            "severity": "critical", "finding_id": None,
            "signals": [{"category": "contained", "title": "Contained by your security team",
                         "detail": msg, "evidence": "", "weight": 1.0}],
            "contained": {"until": _epoch(c["expires_at"]), "scope": c["scope"],
                          "message": msg}}


def record_block(db, c: dict) -> None:
    """Count one refused decision on the containment. Best effort: never fails the request."""
    from .models import Containment
    try:
        db.query(Containment).filter(Containment.id == c["id"]).update(
            {Containment.blocked: Containment.blocked + 1, Containment.last_blocked_at: _now()},
            synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()


def check(db, tenant_id: int | None, actor: str = "", agent: str = "",
          token: str = "") -> dict | None:
    """match + verdict + record_block: the containment answer for this caller, or None."""
    c = match(db, tenant_id, actor=actor, agent=agent, token=token)
    if c is None:
        return None
    record_block(db, c)
    return verdict(c)


class ContainmentError(ValueError):
    """A create/release the console sent that cannot be done (user-safe text)."""


def create(db, tenant_id: int, scope: str, target: str, reason: str, hours: float | None,
           by: str, label: str = ""):
    from . import audit_log
    from .models import ApiKey, Agent, Containment
    if scope not in SCOPES:
        raise ContainmentError(f"scope must be one of {', '.join(SCOPES)}")
    target = (target or "").strip()
    if scope == "org":
        target, label = "*", label or "Everything in this organization"
    elif scope == "user":
        target = target.lower()
        if "@" not in target:
            raise ContainmentError("a user is contained by email address")
    elif scope == "device":
        key = db.get(ApiKey, int(target)) if target.isdigit() else None
        if key is None or key.tenant_id != tenant_id:
            raise ContainmentError("no such device key in this organization")
        label = label or key.label or key.actor or f"key {key.id}"
    elif scope == "agent":
        ag = (db.query(Agent).filter(Agent.tenant_id == tenant_id, Agent.name == target)
                .one_or_none())
        if ag is None:
            raise ContainmentError("no such agent in this organization")
    if not target:
        raise ContainmentError("nothing to contain")
    hrs = DEFAULT_HOURS if hours is None else float(hours)
    if not 0 < hrs <= MAX_HOURS:
        raise ContainmentError(f"a containment lasts between a few minutes and {MAX_HOURS} hours")
    now = _now()
    row = Containment(tenant_id=tenant_id, scope=scope, target=target[:320],
                      label=(label or target)[:320], reason=(reason or "")[:500],
                      created_by=(by or "")[:320], created_at=now,
                      expires_at=now + timedelta(hours=hrs))
    db.add(row)
    db.commit()
    db.refresh(row)
    invalidate(tenant_id)
    audit_log.record(db, tenant_id, by, "containment.create", target=row.label,
                     detail={"scope": scope, "hours": round(hrs, 2), "reason": row.reason,
                             "containment_id": row.id})
    return row


def release(db, tenant_id: int, containment_id: int, by: str):
    from . import audit_log
    from .models import Containment
    row = db.get(Containment, containment_id)
    if row is None or row.tenant_id != tenant_id:
        raise ContainmentError("no such containment")
    if row.released_at is None:
        row.released_at, row.released_by = _now(), (by or "")[:320]
        db.commit()
        invalidate(tenant_id)
        audit_log.record(db, tenant_id, by, "containment.release", target=row.label,
                         detail={"scope": row.scope, "containment_id": row.id,
                                 "blocked": row.blocked or 0})
    return row
