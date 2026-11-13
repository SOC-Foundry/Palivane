"""The breach clock: an exposure register with the regulatory timer running.

A finding says regulated data (personal data, health data, a payment card) reached an AI
provider. A regulator says that starts a clock: 72 hours to notify under GDPR, 60 days
under HIPAA, and every security questionnaire asks for the register either way. Nobody
produces that register at the gateway; they describe it in a policy document.

An exposure is opened when a finding with a regulated class is persisted on a live egress
surface and the data actually left: not blocked, not routed down a private lane. It
carries the class, the regime and its deadline, who sent it, where it went, and a drafted
notification. Its status is worked in the console (open → acknowledged → notified →
closed); a finding dismissed as a false positive closes its exposure as "not a breach".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import ExposureRecord, Finding

# What a class means to a regulator, and how long the clock runs. PHI carries both
# regimes; the shorter deadline is the one shown. Hours.
REGIMES = {
    "pii_exposure": ("GDPR Art. 33", 72),
    "phi_exposure": ("HIPAA §164.404 / GDPR Art. 33", 72),
}
STATUSES = ("open", "acknowledged", "notified", "closed")
_EGRESS = {"ai_usage", "llm_io", "a2a", "mcp", "agent_tools"}      # to an AI provider or agent


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _cat(s) -> str:
    c = s.get("category") if isinstance(s, dict) else getattr(s, "category", "")
    return getattr(c, "value", c) or ""


def _check(s) -> str:
    return (s.get("check") if isinstance(s, dict) else getattr(s, "check", "")) or ""


def classes_of(signals) -> list[str]:
    return sorted({_cat(s) for s in signals or [] if _cat(s) in REGIMES})


def left_the_boundary(tenant, finding: Finding, result: dict | None) -> bool:
    """Whether the data actually went out. A verdict is a recommendation; what happened
    depends on the control at the capture point: a confirmed secret/PII leak is stopped on
    every plane in any mode (the certain-leak rule), and a block-level verdict is stopped
    where the org enforces (the gateway for llm_io, the clients elsewhere). Everything else
    passed, in monitor mode by design."""
    result = result or {}
    from .config import settings
    if result.get("confirmed_leak"):
        # The certain-leak rule (main._prompt_verdict: force_block) stops a confirmed
        # secret/PII leak on every plane in any mode, unless it is switched off for the
        # deployment, in which case the data went out like anything else.
        return not settings.gateway_enforce_secrets
    if (finding.recommended_action or "") != "block":
        return True
    if (finding.surface or "") == "llm_io":
        enforce = getattr(tenant, "gateway_enforce", None)
        enforce = settings.gateway_enforce if enforce is None else bool(enforce)
    else:
        enforce = bool(getattr(tenant, "client_enforce", None))
    return not enforce


def qualifies(finding: Finding, signals, result: dict | None = None, tenant=None) -> list[str]:
    """The regulated classes this finding exposed, or [] when it is not an exposure: the
    data had to leave (not stopped, not routed down a lane), on a live egress surface."""
    if (finding.surface or "") not in _EGRESS:
        return []
    if any(_check(s) == "routed" for s in signals or []):
        return []
    if (result or {}).get("development"):
        return []
    if not left_the_boundary(tenant, finding, result):
        return []
    return classes_of(signals)


def open_for(db: Session, tenant_id: int | None, finding: Finding, signals, result: dict | None = None,
             tenant=None, now: datetime | None = None) -> ExposureRecord | None:
    """Open the exposure for a just-persisted finding, if it is one. One per finding."""
    if tenant_id is None or finding is None or not finding.id:
        return None
    classes = qualifies(finding, signals, result, tenant)
    if not classes:
        return None
    try:
        if db.query(ExposureRecord.id).filter(ExposureRecord.tenant_id == tenant_id,
                                              ExposureRecord.finding_id == finding.id).first():
            return None
        now = now or _now()
        regime, hours = min((REGIMES[c] for c in classes), key=lambda r: r[1])
        row = ExposureRecord(
            tenant_id=tenant_id, finding_id=finding.id, classes=",".join(classes),
            regime=regime, opened_at=now, deadline_at=now + timedelta(hours=hours),
            actor=(finding.sender or "")[:320], destination=(finding.channel or finding.surface or "")[:128],
            surface=(finding.surface or "")[:32], status="open")
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    except Exception:
        db.rollback()
        return None


def draft_notification(row: ExposureRecord, finding: Finding | None) -> str:
    """A first draft of the notification a regulator or a data subject gets: the facts the
    register holds, in plain words, with the gaps named for a person to fill."""
    classes = {"pii_exposure": "personal data", "phi_exposure": "health information"}
    what = " and ".join(classes.get(c, c) for c in (row.classes or "").split(",") if c) or "regulated data"
    evidence = ""
    if finding is not None:
        kinds = sorted({(s.get("evidence") or "")[:60] for s in (finding.signals or [])
                        if _cat(s) in REGIMES and s.get("evidence")})
        if kinds:
            evidence = f" The detector identified: {', '.join(kinds)}."
    when = row.opened_at.strftime("%Y-%m-%d %H:%M UTC") if row.opened_at else "an unknown time"
    return (
        f"Notification of a personal-data exposure ({row.regime})\n\n"
        f"On {when}, {what} was sent by {row.actor or 'an unidentified user'} to an external AI service "
        f"({row.destination or 'unknown destination'}) and was not stopped before it left.{evidence}\n\n"
        f"Detection: Palivane finding #{row.finding_id}, recorded at the moment of transmission.\n"
        f"Nature of the data: {what}. Number of data subjects: [to be determined].\n"
        f"Likely consequences: [to be assessed].\n"
        f"Measures taken: [containment / rotation / deletion request to the provider / notification of subjects].\n"
        f"Contact: [data protection officer].\n"
    )


def summarise(row: ExposureRecord, finding: Finding | None, now: datetime | None = None) -> dict:
    now = now or _now()
    status = row.status or "open"
    closed_reason = row.closed_reason or ""
    if finding is not None and finding.status == "dismissed" and status != "closed":
        # A review that says the detector was wrong closes the exposure: there was no data.
        if finding.review_reason == "false_positive":
            status, closed_reason = "closed", "false_positive"
    remaining = (row.deadline_at - now).total_seconds() / 3600 if row.deadline_at else None
    return {
        "id": row.id, "finding_id": row.finding_id,
        "classes": [c for c in (row.classes or "").split(",") if c], "regime": row.regime,
        "actor": row.actor, "destination": row.destination, "surface": row.surface,
        "opened_at": row.opened_at.isoformat() if row.opened_at else None,
        "deadline_at": row.deadline_at.isoformat() if row.deadline_at else None,
        "hours_left": round(remaining, 1) if remaining is not None else None,
        "overdue": bool(remaining is not None and remaining < 0 and status in ("open", "acknowledged")),
        "status": status, "closed_reason": closed_reason, "note": row.note or "",
        "acknowledged_by": row.acknowledged_by or "",
        "acknowledged_at": row.acknowledged_at.isoformat() if row.acknowledged_at else None,
        "notified_at": row.notified_at.isoformat() if row.notified_at else None,
        "closed_at": row.closed_at.isoformat() if row.closed_at else None,
        "finding": {"severity": finding.severity, "subject": finding.subject, "status": finding.status,
                    "review_reason": finding.review_reason or ""} if finding else None,
        "draft": draft_notification(row, finding),
    }


def listing(db: Session, tenant_id: int, include_closed: bool = False, now: datetime | None = None) -> list[dict]:
    now = now or _now()
    rows = (db.query(ExposureRecord).filter(ExposureRecord.tenant_id == tenant_id)
              .order_by(ExposureRecord.deadline_at.asc()).limit(500).all())
    ids = [r.finding_id for r in rows]
    findings = {f.id: f for f in db.query(Finding).filter(Finding.id.in_(ids)).all()} if ids else {}
    out = [summarise(r, findings.get(r.finding_id), now) for r in rows]
    if not include_closed:
        out = [o for o in out if o["status"] != "closed"]
    # The clock that runs out first comes first; closed ones last.
    out.sort(key=lambda o: (o["status"] == "closed", o["deadline_at"] or ""))
    return out


def set_status(db: Session, tenant_id: int, exposure_id: int, status: str, by: str,
               note: str = "", reason: str = "", now: datetime | None = None) -> ExposureRecord | None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    row = (db.query(ExposureRecord).filter(ExposureRecord.tenant_id == tenant_id,
                                           ExposureRecord.id == exposure_id).one_or_none())
    if row is None:
        return None
    now = now or _now()
    row.status = status
    if note:
        row.note = note[:1000]
    if status == "acknowledged" and not row.acknowledged_at:
        row.acknowledged_at, row.acknowledged_by = now, (by or "")[:320]
    if status == "notified":
        row.notified_at = row.notified_at or now
        row.acknowledged_at, row.acknowledged_by = row.acknowledged_at or now, row.acknowledged_by or (by or "")[:320]
    if status == "closed":
        row.closed_at, row.closed_reason = now, (reason or "resolved")[:32]
    else:
        row.closed_at, row.closed_reason = None, ""
    db.commit()
    db.refresh(row)
    return row
