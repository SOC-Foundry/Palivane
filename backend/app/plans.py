"""Plan / licensing tiers (Free · Team · Enterprise).

The plan is the licensing unit for both self-serve teams and enterprises: it decides
which features a tenant may configure and the default resource quotas it inherits.
Operator-set only (`python -m app.users set-plan`) — upgrades are sales-led ("contact
us"), so there is deliberately no API for a tenant to change its own plan.

Quota precedence: tenant override column > plan default > WARDEN_QUOTA_* global.
Feature gates are enforced server-side at the endpoints that *configure* a gated
feature (an org that configured SSO while Enterprise keeps working if the plan record
ever lapses operationally — we gate setup, not day-to-day auth of existing users).
"""
from __future__ import annotations

from fastapi import HTTPException

from .models import Tenant

# Feature keys:
#   device_setup — self-serve per-OS device installers   (all plans, incl. Free)
#   alerts       — webhook alerting + digests            (Team+)
#   mdm          — MDM policy pack (Jamf/Intune/GPO)      (Team+)
#   sso          — SSO: OIDC and SAML                    (Enterprise)
#   siem         — SIEM HTTP forwarding (Splunk/CEF/...) (Enterprise)
#   s3_delivery  — findings delivery to S3               (Enterprise)
PLANS: dict[str, dict] = {
    "free": {
        "label": "Free",
        # device_setup is free so any org can self-serve onboard its whole fleet (the
        # per-OS installers); the MDM policy pack (Jamf/Intune/GPO) stays a paid feature.
        "features": frozenset({"device_setup"}),
        "quotas": {"users": 5, "api_keys": 10, "ingest_per_day": 2000},
    },
    "team": {
        "label": "Team",
        "features": frozenset({"alerts", "mdm", "device_setup"}),
        "quotas": {},   # inherit the globals
    },
    "enterprise": {
        "label": "Enterprise",
        "features": frozenset({"alerts", "mdm", "sso", "siem", "s3_delivery", "device_setup"}),
        "quotas": {},
    },
}

PLAN_NAMES = tuple(PLANS)   # ("free", "team", "enterprise")

# Feature -> the plan named in the 402 message (the cheapest plan that has it).
_NEEDED_PLAN = {f: next(p for p in PLAN_NAMES if f in PLANS[p]["features"])
                for p in PLAN_NAMES for f in PLANS[p]["features"]}


def plan_of(tenant: Tenant | None) -> str:
    """The tenant's effective plan: its own column, lifted by the instance license when
    one is present (self-hosted deployments carry a vendor-signed license instead of an
    operator-set column — see app/licensing.py). The higher tier wins."""
    from .licensing import PLAN_RANK, licensed_plan
    p = (getattr(tenant, "plan", "") or "").strip().lower()
    p = p if p in PLANS else "free"
    lic = licensed_plan()
    return lic if PLAN_RANK.get(lic, 0) > PLAN_RANK.get(p, 0) else p


def has_feature(tenant: Tenant | None, feature: str) -> bool:
    return feature in PLANS[plan_of(tenant)]["features"]


def plan_quota(tenant: Tenant | None, name: str) -> int:
    """The plan-default quota for `name` (users | api_keys | ingest_per_day); 0 = none set.
    A licensed instance's seat count is the users quota (tenant override still wins)."""
    if name == "users":
        from .licensing import licensed_seats
        seats = licensed_seats()
        if seats:
            return seats
    return PLANS[plan_of(tenant)]["quotas"].get(name, 0)


def require_feature(tenant: Tenant | None, feature: str) -> None:
    """402 with an upgrade pointer when the tenant's plan lacks `feature`."""
    if has_feature(tenant, feature):
        return
    needed = PLANS[_NEEDED_PLAN[feature]]["label"]
    raise HTTPException(
        status_code=402,
        detail=f"this feature requires the {needed} plan (current: "
               f"{PLANS[plan_of(tenant)]['label']}) — contact "
               "sales@tachtech.net to upgrade")


def features_of(tenant: Tenant | None) -> list[str]:
    """Sorted feature list for the console (client-side hints only — never authority)."""
    return sorted(PLANS[plan_of(tenant)]["features"])


# Human-readable feature catalog for the in-console entitlements panel — the display
# strings live next to the gate definitions so the two can't drift.
FEATURE_LABELS: dict[str, str] = {
    "device_setup": "Self-serve device installers (per-OS)",
    "alerts": "Webhook alerts + digests",
    "mdm": "MDM policy pack (Jamf · Intune · GPO)",
    "sso": "SSO — OIDC & SAML",
    "siem": "SIEM forwarding (Splunk HEC · CEF · JSON)",
    "s3_delivery": "S3 / data-lake delivery",
}
# Order features present-to-absent across tiers for a stable comparison table.
_FEATURE_ORDER = ("device_setup", "alerts", "mdm", "sso", "siem", "s3_delivery")


def catalog(tenant: Tenant | None = None) -> dict:
    """Tier → entitlements map for the console (source of truth for the comparison table).
    Includes the caller's current effective plan when a tenant is given."""
    return {
        "current": plan_of(tenant) if tenant is not None else None,
        "features": [{"key": k, "label": FEATURE_LABELS[k]} for k in _FEATURE_ORDER],
        "tiers": [
            {"name": p, "label": PLANS[p]["label"],
             "includes": {k: (k in PLANS[p]["features"]) for k in _FEATURE_ORDER},
             "user_quota": PLANS[p]["quotas"].get("users", 0)}  # 0 = no plan cap (global default)
            for p in PLAN_NAMES
        ],
    }
