"""Your record: what Palivane holds about one person, told to that person.

Every product in this space watches employees and shows the result to the security team.
This is the other direction: any signed-in user can see, for themselves, what was captured
in their AI use, what was stopped and what was only recorded, whether their prompts are
stored or only their metadata, how long findings are kept, which sensors report from their
machines, whether they are contained right now, and what regulated data of theirs left for a
provider. The same page exports it as JSON, which is a data-subject access request answered
in one click and the record a works council asks for before agreeing to monitoring.

Nothing here grants anything: the summaries are the ones "Your findings" already shows
(masked evidence, never the stored prose), and the export is audited like any other pull.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import settings
from .models import Finding, SensorHeartbeat, Tenant

WINDOW_DAYS = 90


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _stored(tenant: Tenant | None) -> dict:
    content = tenant.store_content if (tenant and tenant.store_content is not None) else settings.store_content
    context = tenant.evidence_context if (tenant and tenant.evidence_context is not None) else False
    days = (tenant.retention_days or 0) if tenant else 0
    return {
        "content": bool(content),
        "evidence_context": bool(context),
        "retention_days": days,
        "what": ("The text of what you sent is stored, redacted of the secrets and personal data it "
                 "matched, so the security team can read the context of a finding."
                 if content else
                 "Only metadata is stored: what matched, where it was going, when. The text of "
                 "what you sent is not kept."),
        "how_long": (f"Findings are deleted {days} days after they were last seen."
                     if days else "Findings are kept until the organisation deletes them."),
    }


def summary(db: Session, tenant: Tenant | None, email: str, mine_rows: list[Finding],
            exposures: list[dict], contained: dict | None) -> dict:
    """The page. `mine_rows` are the caller's findings (main._mine), `exposures` the register
    rows whose actor is the caller, `contained` the active containment on them, if any."""
    now = _now()
    since = now - timedelta(days=WINDOW_DAYS)
    recent = [r for r in mine_rows if r.last_seen and r.last_seen >= since]
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    stopped = recorded = 0
    answered = 0
    for r in recent:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        for c in {s.get("category") or "" for s in (r.signals or [])} - {""}:
            by_category[c] = by_category.get(c, 0) + 1
        if r.channel:
            by_tool[r.channel] = by_tool.get(r.channel, 0) + 1
        if r.recommended_action == "block":
            stopped += 1
        else:
            recorded += 1
        if r.owner_response:
            answered += 1
    first = min((r.created_at for r in mine_rows if r.created_at), default=None)
    last = max((r.last_seen for r in mine_rows if r.last_seen), default=None)

    sensors = (db.query(SensorHeartbeat.plane, SensorHeartbeat.client, SensorHeartbeat.tool,
                        func.max(SensorHeartbeat.last_seen))
                 .filter(SensorHeartbeat.tenant_id == (tenant.id if tenant else None),
                         func.lower(SensorHeartbeat.actor) == email)
                 .group_by(SensorHeartbeat.plane, SensorHeartbeat.client, SensorHeartbeat.tool)
                 .all())
    sensor_rows = [{"plane": p or "", "client": c or "", "tool": t or "",
                    "last_seen": ls.isoformat() if ls else None}
                   for p, c, t, ls in sensors]
    sensor_rows.sort(key=lambda s: s["last_seen"] or "", reverse=True)

    open_exp = [e for e in exposures if e.get("status") in ("open", "acknowledged", "notified")]
    return {
        "email": email,
        "window_days": WINDOW_DAYS,
        "generated_at": now.isoformat(),
        "captured": {
            "findings": len(recent), "all_time": len(mine_rows),
            "stopped": stopped, "recorded": recorded, "answered_by_you": answered,
            "by_status": by_status, "by_severity": by_severity,
            "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])[:10]),
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
        },
        "stored": _stored(tenant),
        "sensors": sensor_rows[:30],
        "contained": contained,
        "left_the_org": {
            "open": len(open_exp), "total": len(exposures),
            "items": [{"id": e["id"], "classes": e.get("classes") or [], "regime": e.get("regime"),
                       "destination": e.get("destination") or e.get("surface"),
                       "opened_at": e.get("opened_at"), "status": e.get("status")}
                      for e in exposures[:20]],
        },
        "rights": {
            "export": "/api/my/record/export",
            "answer": "Every finding of yours can be answered under Your findings; an answer "
                      "is recorded and moves it out of the queue, and a false-alarm answer is "
                      "reviewed by the security team.",
            "contact": settings.sales_email,
        },
    }


def export(db: Session, tenant: Tenant | None, email: str, mine_rows: list[Finding],
           exposures: list[dict], contained: dict | None) -> dict:
    """Everything the page shows plus every finding's summary: the data-subject answer."""
    out = summary(db, tenant, email, mine_rows, exposures, contained)
    out["findings"] = [r.to_summary() for r in mine_rows[:2000]]
    out["note"] = ("Findings carry masked evidence (what matched, with the matched value hidden), "
                   "never the full text of what was sent, even where the organisation stores it.")
    return out
