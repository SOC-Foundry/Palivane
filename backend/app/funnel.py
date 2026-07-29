"""Signup → activation funnel — vendor-side product analytics, computed from data we
already store (no external analytics SaaS, no new write-path, no tracking pixels — which
would also break our own CSP/trust posture).

Hosted signups start a full-featured trial; the question that matters is where new orgs
drop off between signing up and getting value. Every stage below is a monotonic subset of the previous
one and is reconstructed from existing timestamps:

  1. signed_up   — a Tenant row exists
  2. verified    — has >=1 email-verified user (cleared the signup email gate)
  3. connected   — has >=1 capture key or enrollment token (wired a source)
  4. activated   — has >=1 finding (a plane actually reported — first value)
  5. retained    — has a finding in the last 7 days (still live)

Also surfaces median time-to-activate and the list of stuck orgs (verified but never
activated) with their age — the actionable "who to reach out to" output.

Internal orgs (tachtech, demo) skew a tiny funnel, so they're excluded by default.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import ApiKey, EnrollmentToken, Finding, Tenant, User

INTERNAL_SLUGS = ("tachtech", "demo")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def compute(db: Session, days: int | None = None,
            include_internal: bool = False) -> dict:
    """Aggregate the funnel. `days` limits to orgs created in the last N days (None = all).
    Returns stage counts, stage-to-stage conversion, median days-to-activate, and stuck orgs."""
    now = _now()
    q = db.query(Tenant)
    if not include_internal:
        q = q.filter(Tenant.slug.notin_(INTERNAL_SLUGS))
    if days:
        q = q.filter(Tenant.created_at >= now - timedelta(days=days))
    tenants = q.all()
    tids = [t.id for t in tenants]

    # One grouped query per downstream table, then set-membership in Python — cheap at this
    # scale and avoids N+1. Empty tids short-circuits to empty sets.
    def _tenant_set(model) -> set[int]:
        if not tids:
            return set()
        rows = (db.query(model.tenant_id)
                .filter(model.tenant_id.in_(tids)).distinct().all())
        return {r[0] for r in rows}

    verified = {u_tid for (u_tid,) in (
        db.query(User.tenant_id).filter(User.tenant_id.in_(tids or [-1]),
                                        User.email_verified.is_(True)).distinct().all())}
    has_key = _tenant_set(ApiKey) | _tenant_set(EnrollmentToken)
    has_finding = _tenant_set(Finding)
    recent_cut = now - timedelta(days=7)
    retained = {r[0] for r in (
        db.query(Finding.tenant_id).filter(Finding.tenant_id.in_(tids or [-1]),
                                           Finding.created_at >= recent_cut).distinct().all())}

    # First-finding timestamp per tenant → time-to-activate.
    first_finding: dict[int, datetime] = {}
    if tids:
        for tid, ts in (db.query(Finding.tenant_id, func.min(Finding.created_at))
                        .filter(Finding.tenant_id.in_(tids)).group_by(Finding.tenant_id).all()):
            first_finding[tid] = ts

    stages = {
        "signed_up": len(tenants),
        "verified": sum(1 for t in tenants if t.id in verified),
        "connected": sum(1 for t in tenants if t.id in has_key),
        "activated": sum(1 for t in tenants if t.id in has_finding),
        "retained": sum(1 for t in tenants if t.id in retained),
    }

    ttas = sorted((first_finding[t.id] - t.created_at).total_seconds() / 86400
                  for t in tenants if t.id in first_finding and t.created_at)
    median_days = round(ttas[len(ttas) // 2], 1) if ttas else None

    # Stuck: verified (real intent) but never activated — the outreach list, oldest first.
    stuck = sorted(
        ({"slug": t.slug, "age_days": round((now - t.created_at).total_seconds() / 86400, 1),
          "connected": t.id in has_key}
         for t in tenants if t.id in verified and t.id not in has_finding),
        key=lambda x: -x["age_days"])

    def _pct(n: int, d: int) -> float:
        return round(100.0 * n / d, 1) if d else 0.0

    return {
        "window_days": days,
        "include_internal": include_internal,
        "stages": stages,
        "conversion": {
            "verified_of_signed_up": _pct(stages["verified"], stages["signed_up"]),
            "connected_of_verified": _pct(stages["connected"], stages["verified"]),
            "activated_of_connected": _pct(stages["activated"], stages["connected"]),
            "activated_of_signed_up": _pct(stages["activated"], stages["signed_up"]),
            "retained_of_activated": _pct(stages["retained"], stages["activated"]),
        },
        "median_days_to_activate": median_days,
        "stuck_orgs": stuck,
    }
