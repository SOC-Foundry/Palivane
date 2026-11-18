"""The assessment closeout: one document a security lead can forward at the end of a trial.

Every number is read from data the console already stores. Nothing here detects. Capture
coverage uses the same plane names as ``/api/setup-status`` and the same surface counts as
``/api/stats``. Unsanctioned tools are the discovery inventory. Confirmed secrets and personal
data are findings whose stored signals already pass ``confirmed_leak`` — a high-entropy guess
is not counted. Precision is the readout. The enforce date is a recommendation from those
facts and the trial clock, and it is omitted when the facts do not support one.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import settings
from .detectors.shadow_ai import CONTACT_LIST_TITLE, CUSTOM_PATTERN_TITLE, HIGH_ENTROPY_TITLE
from .models import Finding, SensorHeartbeat, Tenant
from .precision import MIN_JUDGED

# The setup-status plane, the finding surface it counts, and the sensor plane (if any)
# whose heartbeat means the plane is installed even when it has raised nothing.
# Keep the names aligned with main.setup_status.
PLANES = (
    ("gateway", "llm_io", None, "Gateway"),
    ("shadow_ai", "ai_usage", "ai-usage", "Browser and proxy"),
    ("mcp", "mcp", "mcp", "MCP"),
    ("secrets", "secrets", None, "Secrets at rest"),
)
_CONFIRMED = ("secret_leak", "pii_exposure", "phi_exposure")
_NOT_CONFIRMED = (HIGH_ENTROPY_TITLE, CONTACT_LIST_TITLE, CUSTOM_PATTERN_TITLE)
_FINDING_CAP = 20_000
_TOP_ACTORS = 5
ASSESSMENT_DAYS = 7


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _confirmed_categories(signals) -> set[str]:
    """Categories on this finding that ``confirmed_leak`` would treat as certain.

    Read off the signals already stored. This does not re-scan the text, so a finding
    the engine never raised cannot appear here.
    """
    out: set[str] = set()
    for s in signals or []:
        if not isinstance(s, dict):
            continue
        cat = s.get("category") or ""
        if cat in _CONFIRMED and (s.get("title") or "") not in _NOT_CONFIRMED:
            out.add(cat)
    return out


def _already_enforcing(tenant: Tenant | None) -> bool:
    """True when the org has turned enforce on for the gateway or the capture clients.

    Confirmed leaks still block in monitor mode (``gateway_enforce_secrets``). That is not
    enforce mode, and recommending a switch must not pretend it is.
    """
    gw = settings.gateway_enforce
    cl = settings.client_enforce
    if tenant is not None:
        if tenant.gateway_enforce is not None:
            gw = bool(tenant.gateway_enforce)
        if tenant.client_enforce is not None:
            cl = bool(tenant.client_enforce)
    return bool(gw or cl or settings.mcp_enforce)


def recommend_enforce(now: datetime, *, reporting: bool, judged: int, verdict: str,
                      hint: str, already: bool, trial_ends_at: datetime | None,
                      trial_days: int, min_judged: int = MIN_JUDGED) -> dict:
    """When, if ever, the existing evidence supports leaving monitor mode.

    ``ready`` means the date is a day to switch. A date with ``ready`` false is only a day
    to look again. No date means this window does not support a recommendation.
    """
    if already:
        return {"date": None, "ready": False, "already": True,
                "reason": "Enforcement is already on, so there is no date to switch."}
    if not reporting:
        return {"date": None, "ready": False, "already": False,
                "reason": "No capture plane reported in this window, so there is nothing to enforce on yet."}

    assessment_end = None
    if trial_ends_at is not None:
        back = max(int(trial_days) - ASSESSMENT_DAYS, 0)
        assessment_end = (trial_ends_at - timedelta(days=back)).date()

    if verdict == "ok":
        if assessment_end and assessment_end > now.date():
            return {"date": assessment_end.isoformat(), "ready": True, "already": False,
                    "reason": "The checks reviewed so far are holding. Switch to enforce when the assessment window closes."}
        return {"date": now.date().isoformat(), "ready": True, "already": False,
                "reason": "The checks reviewed in this window are holding, and a capture plane is reporting. Today is a sound day to switch to enforce."}

    if verdict == "low_sample" or judged < min_judged:
        if assessment_end and assessment_end > now.date():
            return {"date": assessment_end.isoformat(), "ready": False, "already": False,
                    "reason": (f"Stay in monitor through the assessment. {judged} "
                               f"{'finding has' if judged == 1 else 'findings have'} been reviewed; "
                               f"the readout needs {min_judged} before enforce is a fair call.")}
        return {"date": None, "ready": False, "already": False,
                "reason": (f"Not enough reviewed findings to recommend a switch "
                           f"({judged} of {min_judged}).")}

    revisit = None
    if trial_ends_at is not None and trial_ends_at.date() >= now.date():
        revisit = trial_ends_at.date().isoformat()
    reason = "The precision readout does not support enforce yet."
    if hint:
        reason = f"{reason} {hint}"
    if revisit:
        reason += " Revisit on the last day of the trial."
    return {"date": revisit, "ready": False, "already": False, "reason": reason}


def _surface_counts(db: Session, tenant_id: int, since: datetime | None) -> dict[str, int]:
    q = db.query(Finding.surface, func.count(Finding.id)).filter(Finding.tenant_id == tenant_id)
    if since is not None:
        q = q.filter(Finding.last_seen >= since)
    return {s or "": n for s, n in q.group_by(Finding.surface).all()}


def build_closeout(db: Session, tenant_id: int, days: int = ASSESSMENT_DAYS,
                   *, sanctioned: str = "", now: datetime | None = None) -> dict:
    """The closeout payload. ``sanctioned`` is the tenant's allowlist, the same string
    ``/api/discovery/inventory`` classifies with."""
    from .discovery import build_inventory
    from .precision import readout

    days = max(1, min(int(days), 365))
    now = now or _now()
    since = now - timedelta(days=days)
    day_ago = now - timedelta(hours=24)

    window_counts = _surface_counts(db, tenant_id, since)
    recent_counts = _surface_counts(db, tenant_id, day_ago)
    sensors = dict(
        db.query(SensorHeartbeat.plane, func.count(func.distinct(SensorHeartbeat.actor)))
        .filter(SensorHeartbeat.tenant_id == tenant_id,
                SensorHeartbeat.last_seen >= since,
                SensorHeartbeat.actor != "")
        .group_by(SensorHeartbeat.plane).all()
    )

    planes = []
    reporting = 0
    for key, surface, heartbeat, label in PLANES:
        findings = int(window_counts.get(surface, 0))
        sensors_n = int(sensors.get(heartbeat, 0)) if heartbeat else 0
        live = findings > 0 or sensors_n > 0
        if live:
            reporting += 1
        planes.append({
            "plane": key,
            "label": label,
            "findings": findings,
            "last_24h": int(recent_counts.get(surface, 0)),
            "sensors": sensors_n,
            "reporting": live,
        })

    inv = build_inventory(db, tenant_id, sanctioned or "")
    unsanctioned = [{
        "tool": t.get("tool") or "",
        "domain": t.get("domain") or "",
        "users": t.get("user_count") or 0,
        "events": t.get("events") or 0,
        "sensitive_events": t.get("sensitive_events") or 0,
    } for t in inv.get("tools") or [] if not t.get("sanctioned")]

    cols = (Finding.sender, Finding.signals, Finding.surface)
    loaded = (db.query(*cols)
              .filter(Finding.tenant_id == tenant_id, Finding.last_seen >= since)
              .limit(_FINDING_CAP + 1).all())
    truncated = len(loaded) > _FINDING_CAP
    loaded = loaded[:_FINDING_CAP]

    confirmed = {"secrets": 0, "pii": 0, "phi": 0, "findings": 0}
    by_actor: dict[str, dict] = {}
    for sender, signals, _surface in loaded:
        cats = _confirmed_categories(signals)
        if cats:
            confirmed["findings"] += 1
            if "secret_leak" in cats:
                confirmed["secrets"] += 1
            if "pii_exposure" in cats:
                confirmed["pii"] += 1
            if "phi_exposure" in cats:
                confirmed["phi"] += 1
        if sender:
            slot = by_actor.setdefault(sender, {"actor": sender, "findings": 0, "confirmed": 0})
            slot["findings"] += 1
            if cats:
                slot["confirmed"] += 1
    top = sorted(by_actor.values(), key=lambda a: (-a["findings"], a["actor"]))[:_TOP_ACTORS]

    prec = readout(db, tenant_id, days, now)
    reviewed = prec.get("reviewed") or {}
    worth = [{
        "check": c.get("check") or "",
        "title": c.get("title") or "",
        "judged": c.get("judged") or 0,
        "actionable": c.get("actionable") or 0,
        "verdict": c.get("verdict") or "",
        "hint": c.get("hint") or "",
    } for c in prec.get("checks") or [] if c.get("verdict") not in ("ok", "low_sample")][:3]

    tenant = db.get(Tenant, tenant_id)
    on_trial = bool(tenant and (tenant.plan or "") == "trial" and tenant.trial_ends_at)
    enforce = recommend_enforce(
        now, reporting=reporting > 0,
        judged=int(reviewed.get("judged") or 0),
        verdict=reviewed.get("verdict") or "low_sample",
        hint=reviewed.get("hint") or "",
        already=_already_enforcing(tenant),
        trial_ends_at=tenant.trial_ends_at if on_trial else None,
        trial_days=settings.trial_days,
        min_judged=int((prec.get("limits") or {}).get("min_judged") or MIN_JUDGED),
    )
    return {
        "days": days,
        "generated_at": now.isoformat(),
        "truncated": truncated,
        # Where each section is read from. The page does not add a detector of its own.
        "sources": ["/api/stats", "/api/setup-status", "/api/discovery/inventory", "/api/precision"],
        "planes": planes,
        "unsanctioned": unsanctioned,
        "unsanctioned_tools": int((inv.get("summary") or {}).get("unsanctioned_tools") or 0),
        "confirmed": confirmed,
        "top_actors": top,
        "precision": {
            "days": prec.get("days"),
            "judged": int(reviewed.get("judged") or 0),
            "actionable": int(reviewed.get("actionable") or 0),
            "actionable_rate": reviewed.get("actionable_rate"),
            "expected": int(reviewed.get("expected") or 0),
            "false_positive": int(reviewed.get("false_positive") or 0),
            "unspecified": int(reviewed.get("unspecified") or 0),
            "verdict": reviewed.get("verdict") or "low_sample",
            "hint": reviewed.get("hint") or "",
            "worth_tuning": worth,
        },
        "enforce": enforce,
    }
