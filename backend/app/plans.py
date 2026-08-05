"""Plan / licensing tiers (Free · Team · Enterprise).

The plan is the licensing unit for both self-serve teams and enterprises: it decides
which features a tenant may configure and the default resource quotas it inherits.
Operator-set only (`python -m app.users set-plan`) — upgrades are sales-led ("contact
us"), so there is deliberately no API for a tenant to change its own plan.

Two different kinds of "free" exist, deliberately:

  * `trial`  — what a hosted signup gets: every feature, for 14 days, so a buyer can see
    findings from their own traffic before paying. On expiry the tenant becomes `expired`
    (see plan_of): gated features switch off and quotas tighten, but capture and detection
    keep working — this is a security control, so a lapsed trial must never silently stop
    protecting a fleet that is still pointed at it.
  * `free`   — the source-available self-host path. An instance with no license file runs
    here indefinitely (see app/licensing.py). Kept fully functional on purpose: running it
    yourself is the honest free option, and it costs the vendor nothing.

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
#   judge        — managed LLM judge (operator-funded)    (Enterprise; SaaS only, when
#                  WARDEN_JUDGE_PLAN_GATED is on — self-hosted brings its own key)
_ALL_FEATURES = frozenset({"alerts", "mdm", "sso", "siem", "s3_delivery", "judge",
                           "device_setup"})

PLANS: dict[str, dict] = {
    "trial": {
        "label": "Trial",
        # Full-featured on purpose: the trial has to prove the product on the buyer's own
        # traffic, and half of what they are evaluating is the fleet/reporting side.
        "features": _ALL_FEATURES,
        "quotas": {},   # inherit the globals
    },
    "expired": {
        "label": "Trial expired",
        # No gated feature may be (re)configured, and quotas tighten — but the capture
        # planes keep reporting, so an expired trial degrades loudly, not silently.
        "features": frozenset(),
        "quotas": {"users": 5, "api_keys": 5, "ingest_per_day": 500},
    },
    "free": {
        "label": "Free (self-hosted)",
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
        "features": frozenset({"alerts", "mdm", "sso", "siem", "s3_delivery", "judge",
                               "device_setup"}),
        "quotas": {},
    },
}

PLAN_NAMES = tuple(PLANS)   # ("trial", "expired", "free", "team", "enterprise")
# The tiers a customer can actually buy — the order used for "which plan do I need?" and
# for the console's comparison table. `trial` and `expired` are states, not products, and
# `free` is the self-host path, so none of them belong in a purchase comparison.
PURCHASABLE = ("team", "enterprise")

# Feature -> the plan named in the 402 message: the cheapest PURCHASABLE plan that has it
# (never "trial", which holds every feature by design and cannot be bought).
_NEEDED_PLAN = {f: next(p for p in PURCHASABLE if f in PLANS[p]["features"])
                for p in PURCHASABLE for f in PLANS[p]["features"]}


def plan_of(tenant: Tenant | None) -> str:
    """The tenant's effective plan: its own column, lifted by the instance license when
    one is present (self-hosted deployments carry a vendor-signed license instead of an
    operator-set column — see app/licensing.py). The higher tier wins."""
    from .licensing import PLAN_RANK, licensed_plan
    p = (getattr(tenant, "plan", "") or "").strip().lower()
    p = p if p in PLANS else "free"
    if p == "trial" and trial_expired(tenant):
        p = "expired"
    lic = licensed_plan()
    return lic if PLAN_RANK.get(lic, 0) > PLAN_RANK.get(p, 0) else p


def trial_expired(tenant: Tenant | None) -> bool:
    """True once a trial tenant is past its end date. No end date = not expired (an
    operator can hand out an open-ended trial by clearing the column)."""
    ends = getattr(tenant, "trial_ends_at", None)
    if ends is None:
        return False
    from datetime import datetime, timezone
    return ends < datetime.now(timezone.utc).replace(tzinfo=None)


def trial_days_left(tenant: Tenant | None) -> int | None:
    """Whole days remaining on a trial (0 once expired); None if not on a trial clock."""
    ends = getattr(tenant, "trial_ends_at", None)
    if ends is None or (getattr(tenant, "plan", "") or "").strip().lower() != "trial":
        return None
    from datetime import datetime, timezone
    delta = ends - datetime.now(timezone.utc).replace(tzinfo=None)
    return max(0, delta.days + (1 if delta.seconds else 0))


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
    current = plan_of(tenant)
    if current == "expired":
        raise HTTPException(
            status_code=402,
            detail="your Palivane trial has ended — contact sales@tachtech.net to pick a plan "
                   "and keep this feature")
    needed = PLANS[_NEEDED_PLAN[feature]]["label"]
    raise HTTPException(
        status_code=402,
        detail=f"this feature requires the {needed} plan (current: "
               f"{PLANS[current]['label']}) — contact "
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
    "judge": "Managed LLM judge (semantic detection)",
}
# Order features present-to-absent across tiers for a stable comparison table.
_FEATURE_ORDER = ("device_setup", "alerts", "mdm", "sso", "siem", "s3_delivery", "judge")


def catalog(tenant: Tenant | None = None) -> dict:
    """Tier → entitlements map for the console (source of truth for the comparison table).
    Includes the caller's current effective plan when a tenant is given."""
    current = plan_of(tenant) if tenant is not None else None
    # Show what they can buy — plus their own tier when it isn't one of those (trial,
    # expired, self-hosted free), so the table always has a column for "where I am now".
    shown = ([current] if current and current not in PURCHASABLE else []) + list(PURCHASABLE)
    return {
        "current": current,
        "features": [{"key": k, "label": FEATURE_LABELS[k]} for k in _FEATURE_ORDER],
        "tiers": [
            {"name": p, "label": PLANS[p]["label"],
             "includes": {k: (k in PLANS[p]["features"]) for k in _FEATURE_ORDER},
             "user_quota": PLANS[p]["quotas"].get("users", 0),  # 0 = no plan cap (global default)
             "purchasable": p in PURCHASABLE}
            for p in shown
        ],
    }
