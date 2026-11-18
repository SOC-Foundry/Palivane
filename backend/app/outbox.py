"""Durable outbox for SIEM and alert delivery.

Capture inserts a row and returns. Nothing on that path opens a socket. A lifespan
loop claims due rows, delivers them, and retries with backoff. A row that still
fails after MAX_ATTEMPTS, or that fails for a reason that will not change by
waiting (the sink was removed, the URL is blocked), is marked `dead` and left for
the status page.

Several instances run the loop. A claim is a conditional update from `pending` to
`inflight`, so only one of them sends a given row. If the sender dies, the lease
expires and another instance picks the row up. That is at-least-once: a crash
after the HTTP call and before the commit can send the event twice. The payload
carries `delivery_id` (the outbox row id) so a collector can drop the duplicate.

The row stores the event, not the credential. The sender reads the tenant's
current webhook, SIEM URL, or S3 role, so a token rotated while the event was
queued is the one that gets used.
"""

from __future__ import annotations

import logging
import os
import socket
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

log = logging.getLogger("uvicorn.error")

SINKS = ("alert", "siem_http", "siem_s3")
MAX_ATTEMPTS = 8
LEASE_SECONDS = 45
BATCH = 32
# Delivered rows are not the record of "last success" (that is delivery_cursors);
# they only have to stay long enough to explain a recent duplicate.
KEEP_DELIVERED_DAYS = 7
KEEP_DEAD_DAYS = 30
KEEP_AUDIT_DAYS = 90

# Tests that still want the send to happen inside the request set this. Production
# leaves it false: capture must not wait on the collector.
INLINE = False

INTERVAL = max(0.5, float(os.getenv("PALIVANE_OUTBOX_INTERVAL", "2")))

_BACKOFF_BASE = 5
_BACKOFF_FACTOR = 3
_prune_tick = 0


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _worker() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"[:120]


def _backoff(attempts: int) -> int:
    """Seconds to wait after `attempts` failures. Caps at an hour."""
    step = max(attempts, 1) - 1
    return min(3600, _BACKOFF_BASE * (_BACKOFF_FACTOR ** step))


def _permanent(detail: str) -> bool:
    """Failures that retrying will not fix."""
    d = (detail or "").lower()
    return (
        "no longer configured" in d
        or "not configured" in d
        or "url blocked" in d
        or "no siem url" in d
        or "bucket plus" in d
    )


def enqueue(db: Session, tenant_id: int | None, sink: str, payload: dict) -> None:
    """Add one delivery to the caller's transaction. Does not commit and does not send.

    The caller's commit is what makes the row durable. A rollback of the finding
    rolls the delivery back with it, so a SIEM event is never queued for a finding
    that was not stored.
    """
    if not tenant_id or sink not in SINKS:
        return
    from .models import DeliveryOutbox
    row = DeliveryOutbox(
        tenant_id=int(tenant_id), sink=sink, payload=payload or {},
        status="pending", attempts=0, next_attempt_at=_now(),
        last_error="", claimed_by="", created_at=_now(),
    )
    db.add(row)
    if INLINE:
        db.flush()
        _send_and_settle(db, row)


def _cursor(db: Session, tenant_id: int, sink: str):
    from .models import DeliveryCursor
    row = (db.query(DeliveryCursor)
           .filter(DeliveryCursor.tenant_id == tenant_id, DeliveryCursor.sink == sink)
           .one_or_none())
    if row is None:
        row = DeliveryCursor(tenant_id=tenant_id, sink=sink, dead_count=0, last_error="")
        db.add(row)
    return row


def _settle(db: Session, row, ok: bool, detail: str, permanent: bool) -> None:
    from . import sink_health
    now = _now()
    cur = _cursor(db, row.tenant_id, row.sink)
    row.claimed_by = ""
    row.claimed_until = None
    if ok:
        row.status = "delivered"
        row.delivered_at = now
        row.last_error = ""
        cur.last_success_at = now
    else:
        row.last_error = (detail or "delivery failed")[:300]
        cur.last_failure_at = now
        cur.last_error = row.last_error
        if permanent or (row.attempts or 0) >= MAX_ATTEMPTS:
            row.status = "dead"
            cur.dead_count = (cur.dead_count or 0) + 1
        else:
            row.status = "pending"
            row.next_attempt_at = now + timedelta(seconds=_backoff(row.attempts or 1))
    sink_health.record(row.tenant_id, row.sink, ok, "" if ok else row.last_error)


def _send_and_settle(db: Session, row) -> None:
    try:
        ok, detail, permanent = _deliver(db, row)
    except Exception as e:  # noqa: BLE001  a sink bug must become a retry, not a stuck lease
        log.warning("outbox delivery raised (id %s): %s", row.id, e)
        ok, detail, permanent = False, str(e)[:300], False
    _settle(db, row, ok, detail, permanent)


def _deliver(db: Session, row) -> tuple[bool, str, bool]:
    """Send one row using the tenant's current configuration. (ok, detail, permanent)."""
    from .models import Tenant
    tenant = db.get(Tenant, row.tenant_id)
    if tenant is None:
        return False, "tenant no longer exists", True
    body = dict(row.payload or {})
    body["delivery_id"] = row.id
    if row.sink == "alert":
        return _deliver_alert(tenant, body)
    if row.sink == "siem_http":
        return _deliver_http(tenant, body)
    if row.sink == "siem_s3":
        return _deliver_s3(tenant, body)
    return False, f"unknown sink {row.sink}", True


def _deliver_alert(tenant, body: dict) -> tuple[bool, str, bool]:
    from . import alerts
    url = (tenant.alert_webhook or "").strip()
    if not url:
        return False, "alert webhook no longer configured", True
    ok, detail = alerts.send_result(url, body)
    return ok, detail, _permanent(detail)


def _deliver_http(tenant, body: dict) -> tuple[bool, str, bool]:
    from . import crypto, siem
    url = (tenant.siem_url or "").strip()
    if not url:
        return False, "SIEM URL no longer configured", True
    token = crypto.unseal_secret(
        tenant.siem_token, crypto.tenant_dek_readonly(tenant), legacy_plaintext=True)
    ok, detail = siem.send_detail(url, token, tenant.siem_format or "json", body)
    return ok, detail, _permanent(detail)


def _deliver_s3(tenant, body: dict) -> tuple[bool, str, bool]:
    from . import crypto, siem_s3
    bucket = (tenant.siem_s3_bucket or "").strip()
    role = (getattr(tenant, "siem_s3_role_arn", "") or "").strip()
    key_id = (tenant.siem_s3_key_id or "").strip()
    secret = crypto.unseal_secret(
        tenant.siem_s3_secret, crypto.tenant_dek_readonly(tenant), legacy_plaintext=True)
    if not (bucket and (role or (key_id and secret))):
        return False, "S3 sink no longer configured", True
    ok, detail = siem_s3._put(
        bucket, tenant.siem_s3_prefix or "", tenant.siem_s3_region or "",
        key_id, secret, body, role_arn=role,
        external_id=(getattr(tenant, "siem_s3_external_id", "") or ""),
    )
    return ok, detail, _permanent(detail)


def _claim(db: Session, limit: int) -> list[int]:
    """Move up to `limit` due rows to inflight. Only the caller whose update matches
    sends them. Expired leases return to pending first, so a dead worker's rows
    are not stuck."""
    from .models import DeliveryOutbox
    now = _now()
    until = now + timedelta(seconds=LEASE_SECONDS)
    worker = _worker()
    (db.query(DeliveryOutbox)
     .filter(DeliveryOutbox.status == "inflight",
             DeliveryOutbox.claimed_until.isnot(None),
             DeliveryOutbox.claimed_until < now)
     .update({DeliveryOutbox.status: "pending", DeliveryOutbox.claimed_by: "",
              DeliveryOutbox.claimed_until: None}, synchronize_session=False))
    ids = [r[0] for r in (
        db.query(DeliveryOutbox.id)
        .filter(DeliveryOutbox.status == "pending",
                DeliveryOutbox.next_attempt_at <= now)
        .order_by(DeliveryOutbox.id)
        .limit(limit)
        .all())]
    claimed = []
    for i in ids:
        n = (db.query(DeliveryOutbox)
             .filter(DeliveryOutbox.id == i, DeliveryOutbox.status == "pending")
             .update({DeliveryOutbox.status: "inflight",
                      DeliveryOutbox.claimed_by: worker,
                      DeliveryOutbox.claimed_until: until,
                      DeliveryOutbox.attempts: DeliveryOutbox.attempts + 1},
                     synchronize_session=False))
        if n:
            claimed.append(i)
    db.commit()
    return claimed


def _prune(db: Session) -> None:
    from .models import CrossTenantAudit, DeliveryOutbox
    now = _now()
    (db.query(DeliveryOutbox)
     .filter(DeliveryOutbox.status == "delivered",
             DeliveryOutbox.delivered_at < now - timedelta(days=KEEP_DELIVERED_DAYS))
     .delete(synchronize_session=False))
    (db.query(DeliveryOutbox)
     .filter(DeliveryOutbox.status == "dead",
             DeliveryOutbox.created_at < now - timedelta(days=KEEP_DEAD_DAYS))
     .delete(synchronize_session=False))
    (db.query(CrossTenantAudit)
     .filter(CrossTenantAudit.created_at < now - timedelta(days=KEEP_AUDIT_DAYS))
     .delete(synchronize_session=False))
    db.commit()


def drain_once(db: Session | None = None, limit: int = BATCH) -> int:
    """Claim and deliver one batch. Returns how many rows were attempted.

    Pass `db` from a test. The lifespan loop calls it with none, and this opens
    a short-lived session that is allowed to see every tenant.
    """
    global _prune_tick
    from .database import SessionLocal, allow_cross_tenant
    own = db is None
    if db is None:
        db = SessionLocal()
    delivered = 0
    try:
        allow_cross_tenant(db, "job.outbox")
        ids = _claim(db, limit)
        for i in ids:
            from .models import DeliveryOutbox
            row = db.get(DeliveryOutbox, i)
            if row is None or row.status != "inflight":
                continue
            _send_and_settle(db, row)
            db.commit()
            delivered += 1
        _prune_tick += 1
        if _prune_tick % 30 == 0:
            _prune(db)
        return delivered
    finally:
        if own:
            db.close()


def snapshot(db: Session, tenant_id: int) -> dict:
    """Backlog, last success, and failures for this tenant. Shared across instances:
    it reads the outbox and the cursors, not this process's memory."""
    from .models import DeliveryCursor, DeliveryOutbox
    counts: dict[str, dict[str, int]] = {s: {"pending": 0, "inflight": 0, "dead": 0} for s in SINKS}
    grouped = (
        db.query(DeliveryOutbox.sink, DeliveryOutbox.status, func.count())
        .filter(DeliveryOutbox.tenant_id == tenant_id,
                DeliveryOutbox.status.in_(("pending", "inflight", "dead")))
        .group_by(DeliveryOutbox.sink, DeliveryOutbox.status)
        .all()
    )
    for sink, status, n in grouped:
        if sink in counts and status in counts[sink]:
            counts[sink][status] = int(n)
    cursors = {
        c.sink: c for c in db.query(DeliveryCursor).filter(DeliveryCursor.tenant_id == tenant_id)
    }
    by_sink = {}
    pending = inflight = dead = 0
    last_success = last_failure = None
    last_error = ""
    for sink in SINKS:
        c = counts[sink]
        cur = cursors.get(sink)
        b = c["pending"] + c["inflight"]
        d = (cur.dead_count or 0) if cur else c["dead"]
        pending += c["pending"]
        inflight += c["inflight"]
        dead += d
        success_at = cur.last_success_at if cur else None
        failure_at = cur.last_failure_at if cur else None
        err = (cur.last_error or "") if cur else ""
        if success_at and (last_success is None or success_at > last_success):
            last_success = success_at
        if failure_at and (last_failure is None or failure_at > last_failure):
            last_failure = failure_at
            last_error = err
        by_sink[sink] = {
            "backlog": b,
            "dead": d,
            "last_success": _iso(success_at),
            "last_failure": _iso(failure_at),
            "last_error": err,
        }
    return {
        "backlog": pending + inflight,
        "pending": pending,
        "inflight": inflight,
        "dead": dead,
        "last_success": _iso(last_success),
        "last_failure": _iso(last_failure),
        "last_error": last_error,
        "by_sink": by_sink,
    }
