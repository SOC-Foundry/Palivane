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
    """Gateway requests/minute for this tenant: its own limit, else the global (0 = off)."""
    if tenant is not None and tenant.rate_limit:
        return tenant.rate_limit
    return settings.gateway_rate_limit


def effective_ingest_limit(tenant: Tenant | None) -> int:
    """Sensor/ingest requests/minute: this tenant's own limit, else the global (0 = off).
    Separate from the gateway budget so agentic capture can't starve LLM traffic."""
    if tenant is not None and getattr(tenant, "ingest_rate_limit", 0):
        return tenant.ingest_rate_limit
    return settings.ingest_rate_limit


def effective_quota(tenant: Tenant | None, name: str) -> int:
    """Resource quota `name` (users | api_keys | ingest_per_day) for this tenant: its own
    override column when set, else its plan's default, else the PALIVANE_QUOTA_* global.
    0 = unlimited."""
    if tenant is not None and getattr(tenant, f"quota_{name}", 0):
        return getattr(tenant, f"quota_{name}")
    if tenant is not None:
        from .plans import plan_quota  # noqa: PLC0415 — avoid an import cycle via models
        limit = plan_quota(tenant, name)
        if limit:
            return limit
    return getattr(settings, f"quota_{name}")


def check_resource_quota(db: Session, tenant_id: int, name: str, current_count: int) -> None:
    """Raise 403 when creating one more of `name` would exceed the tenant's quota.
    Import-light so auth.py can call it at user/key creation without cycles."""
    from fastapi import HTTPException  # noqa: PLC0415

    tenant = db.get(Tenant, tenant_id)
    limit = effective_quota(tenant, name)
    if limit and current_count >= limit:
        from .plans import plan_of  # noqa: PLC0415
        hint = ("contact sales@palivane.io to raise it"
                if plan_of(tenant) != "enterprise"
                else "contact your Palivane operator to raise it")
        raise HTTPException(
            status_code=403,
            detail=f"{name.replace('_', ' ')} quota reached ({limit}), {hint}")


def check_daily_ingest(db: Session, tenant_id: int) -> tuple[bool, int, int]:
    """Sustained-abuse cap on top of the per-minute rate: total ingest requests since
    UTC midnight vs the tenant's daily quota. Returns (allowed, count_today, limit)."""
    tenant = db.get(Tenant, tenant_id)
    limit = effective_quota(tenant, "ingest_per_day")
    if not limit:
        return True, 0, 0
    midnight = _now().replace(hour=0, minute=0, second=0, microsecond=0)
    from sqlalchemy import func  # noqa: PLC0415
    total = (db.query(func.coalesce(func.sum(GatewayUsage.count), 0))
             .filter(GatewayUsage.tenant_id == tenant_id, GatewayUsage.kind == "ingest",
                     GatewayUsage.window_start >= midnight)
             .scalar())
    return total <= limit, int(total), limit


def record_and_check(db: Session, tenant_id: int | None, kind: str = "gateway",
                     limit: int | None = None) -> tuple[bool, int, int]:
    """Count one request in the current minute for `kind` and report whether it's allowed.
    Returns (allowed, count_this_minute, limit). limit==0 means unlimited (always allowed).
    `kind` separates the gateway and sensor-ingest budgets; `limit` overrides the tenant's."""
    if tenant_id is None:
        return True, 0, 0
    tenant = db.get(Tenant, tenant_id)
    if limit is None:
        limit = effective_ingest_limit(tenant) if kind == "ingest" else effective_limit(tenant)
    window = _minute(_now())
    row = (db.query(GatewayUsage)
           .filter(GatewayUsage.tenant_id == tenant_id, GatewayUsage.window_start == window,
                   GatewayUsage.kind == kind)
           .first())
    if row is None:
        row = GatewayUsage(tenant_id=tenant_id, window_start=window, kind=kind, count=0)
        db.add(row)
    row.count += 1
    db.commit()
    allowed = (limit == 0) or (row.count <= limit)
    return allowed, row.count, limit


def usage_summary(db: Session, tenant_id: int, days: int = 7) -> dict:
    """Metering view for a tenant. The headline fields are gateway traffic (LLM calls);
    sensor/ingest counts are reported separately (`ingest_*`)."""
    now = _now()
    since = now - timedelta(days=days)
    rows = (db.query(GatewayUsage)
            .filter(GatewayUsage.tenant_id == tenant_id, GatewayUsage.window_start >= since)
            .all())
    day_totals: dict[str, int] = {}
    cur_window = _minute(now)
    h24 = now - timedelta(hours=24)
    current = last_24h = ingest_current = ingest_24h = 0
    for r in rows:
        if r.kind == "gateway":
            day_totals[r.window_start.date().isoformat()] = day_totals.get(
                r.window_start.date().isoformat(), 0) + r.count
            if r.window_start >= h24:
                last_24h += r.count
            if r.window_start == cur_window:
                current = r.count
        elif r.kind == "ingest":
            if r.window_start >= h24:
                ingest_24h += r.count
            if r.window_start == cur_window:
                ingest_current = r.count
    tenant = db.get(Tenant, tenant_id)
    return {
        "window": "1m",
        "limit_per_min": effective_limit(tenant),
        "current_window": current,
        "last_24h": last_24h,
        "by_day": dict(sorted(day_totals.items())),
        "ingest_limit_per_min": effective_ingest_limit(tenant),
        "ingest_current_window": ingest_current,
        "ingest_last_24h": ingest_24h,
        "quotas": {
            "users": effective_quota(tenant, "users"),
            "api_keys": effective_quota(tenant, "api_keys"),
            "ingest_per_day": effective_quota(tenant, "ingest_per_day"),
            "ingest_today": check_daily_ingest(db, tenant_id)[1],
        },
    }


def prune(db: Session) -> int:
    """Delete usage rows older than the metering horizon. Returns rows removed."""
    cutoff = _now() - timedelta(days=_PRUNE_DAYS)
    n = db.query(GatewayUsage).filter(GatewayUsage.window_start < cutoff).delete()
    db.commit()
    return n
