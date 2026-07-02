"""Per-tenant gateway rate limiting + usage metering (DB-backed, multi-worker safe).

A fixed 60-second window counter per tenant serves both jobs: the current window's count
vs the tenant's limit is the rate check, and summing windows over a period is the usage
metering. One row per tenant per minute; rows past the retention horizon are pruned.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .config import settings
from .models import GatewayUsage, Tenant

_PRUNE_DAYS = 35   # keep ~a month of minute-buckets for metering, then drop


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _minute(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def effective_limit(tenant: Tenant | None) -> int:
    """Requests/minute for this tenant: its own limit, else the global default (0 = off)."""
    if tenant is not None and tenant.rate_limit:
        return tenant.rate_limit
    return settings.gateway_rate_limit


def record_and_check(db: Session, tenant_id: int | None) -> tuple[bool, int, int]:
    """Count one gateway request in the current minute and report whether it's allowed.
    Returns (allowed, count_this_minute, limit). limit==0 means unlimited (always allowed)."""
    if tenant_id is None:
        return True, 0, 0
    tenant = db.get(Tenant, tenant_id)
    limit = effective_limit(tenant)
    window = _minute(_now())
    row = (db.query(GatewayUsage)
           .filter(GatewayUsage.tenant_id == tenant_id, GatewayUsage.window_start == window)
           .first())
    if row is None:
        row = GatewayUsage(tenant_id=tenant_id, window_start=window, count=0)
        db.add(row)
    row.count += 1
    db.commit()
    allowed = (limit == 0) or (row.count <= limit)
    return allowed, row.count, limit


def usage_summary(db: Session, tenant_id: int, days: int = 7) -> dict:
    """Metering view for a tenant: current-window count, last-24h total, and per-day totals."""
    now = _now()
    since = now - timedelta(days=days)
    rows = (db.query(GatewayUsage)
            .filter(GatewayUsage.tenant_id == tenant_id, GatewayUsage.window_start >= since)
            .all())
    day_totals: dict[str, int] = {}
    last_24h = 0
    cur_window = _minute(now)
    current = 0
    h24 = now - timedelta(hours=24)
    for r in rows:
        day_totals[r.window_start.date().isoformat()] = day_totals.get(
            r.window_start.date().isoformat(), 0) + r.count
        if r.window_start >= h24:
            last_24h += r.count
        if r.window_start == cur_window:
            current = r.count
    tenant = db.get(Tenant, tenant_id)
    return {
        "window": "1m",
        "limit_per_min": effective_limit(tenant),
        "current_window": current,
        "last_24h": last_24h,
        "by_day": dict(sorted(day_totals.items())),
    }


def prune(db: Session) -> int:
    """Delete usage rows older than the metering horizon. Returns rows removed."""
    cutoff = _now() - timedelta(days=_PRUNE_DAYS)
    n = db.query(GatewayUsage).filter(GatewayUsage.window_start < cutoff).delete()
    db.commit()
    return n
