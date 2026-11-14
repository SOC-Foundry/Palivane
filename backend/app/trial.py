"""Trial lifecycle notices — the emails that keep a trial from lapsing silently.

The trial's expiry behavior is deliberate (capture keeps running, gated features switch
off — see app/plans.py), but until now it was only visible as a console banner, which
nobody re-opens in week two. This module emails the org's admins at three points:

    d7       — 7 days left: the 7-day assessment — the first week's headline numbers
               (findings, what would have been blocked, tools in use, who is covered)
               and where the full report is — plus what switches off
    d2       — 2 days left (last useful moment to reach out)
    expired  — the clock ran out (what still works, how to pick a plan)

Ticked from the same background loop as alert digests (main.py). Idempotency lives in
`tenants.trial_notice` — the highest stage already sent — and each send is claimed with a
conditional UPDATE (same pattern as run_digests), so multiple workers never double-send.
Only the *currently due* stage goes out: a tenant that was offline past two thresholds
gets one email, not a backlog.

Email-less deployments degrade like every other mail flow: nothing is sent and nothing is
marked, so notices start flowing (from the current stage) if SMTP is configured later.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import email as email_mod
from .config import settings
from .models import Tenant, User

log = logging.getLogger("uvicorn.error")

# Stage -> rank. A notice is due when its stage outranks what was already sent, so a
# shortened/extended trial (operator edits trial_ends_at) never re-sends a lower stage.
_RANK = {"": 0, "d7": 1, "d2": 2, "expired": 3}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def due_stage(tenant: Tenant, now: datetime) -> str:
    """The stage this tenant's clock is at right now ("" = none due yet)."""
    ends = tenant.trial_ends_at
    if ends is None:
        return ""
    if ends < now:
        return "expired"
    days_left = (ends - now).days + (1 if (ends - now).seconds else 0)
    if days_left <= 2:
        return "d2"
    if days_left <= 7:
        return "d7"
    return ""


ASSESSMENT_DAYS = 7


def _assessment(db: Session, tenant_id: int) -> dict | None:
    """The first week's headline numbers, or None when they cannot be computed. A notice
    must never fail because the report did: the mail goes out either way."""
    try:
        from .main import report_numbers   # lazy: main imports this module
        return report_numbers(db, tenant_id, ASSESSMENT_DAYS)
    except Exception:   # noqa: BLE001 - the report is a bonus, the notice is the contract
        log.exception("trial notice: assessment numbers unavailable for tenant %s", tenant_id)
        return None


def _assessment_lines(numbers: dict | None, console: str) -> str:
    """The assessment paragraph of the d7 notice. Numbers are the report's own fields, so
    the mail never says something the Report page would contradict."""
    if not numbers:
        return (f"Your 7-day AI exposure assessment is ready in the console ({console}): "
                "open Report and print it or save it as a PDF.\n\n")
    sev = numbers.get("by_severity") or {}
    tools = list((numbers.get("by_tool") or {}).keys())
    shadow = numbers.get("shadow") or {}
    unsanctioned = shadow.get("unsanctioned_tools") if isinstance(shadow, dict) else None
    lines = [
        "Your 7-day AI exposure assessment",
        f"  Events analyzed:            {numbers.get('analyzed_events', 0)}",
        f"  Findings:                   {numbers.get('findings', 0)} "
        f"(critical {sev.get('critical', 0)}, high {sev.get('high', 0)})",
        f"  Would have been blocked:    {numbers.get('prevented_blocks', 0)}",
        f"  AI tools seen:              {len(tools)}"
        + (f" ({', '.join(tools[:5])})" if tools else ""),
    ]
    if isinstance(unsanctioned, int):
        lines.append(f"  Unsanctioned tools:         {unsanctioned}")
    lines.append(f"  People covered by sensors:  {numbers.get('covered_actors', 0)}, "
                 f"with findings: {numbers.get('actors_with_findings', 0)}")
    if numbers.get("findings", 0) == 0 and numbers.get("covered_actors", 0) == 0:
        lines.append("  Nothing reported yet: no sensor has checked in. The assessment "
                     "starts the day the first machine installs.")
    lines.append("")
    lines.append(f"The full report (by tool, by data class, the precision readout and what to "
                 f"turn on first) is in the console ({console}) under Report. Print it or save "
                 f"it as a PDF; it is written to be forwarded.")
    return "\n".join(lines) + "\n\n"


def _compose(stage: str, tenant: Tenant, days_left: int,
             numbers: dict | None = None) -> tuple[str, str]:
    """(subject, body) for one notice. Plain text, like every other Palivane email."""
    org = tenant.name or tenant.slug
    console = email_mod.base_url()
    upgrade = (f"To keep everything: open the console ({console}), go to Settings → Your "
               f"plan, and hit \"Request upgrade\" — or just reply to {settings.sales_email}.")
    if stage == "expired":
        return (
            f"Your Palivane trial for {org} has ended",
            f"The Palivane trial for \"{org}\" ended today.\n\n"
            "Your fleet is still protected: capture and detection keep running, and your "
            "findings are intact. But paid features (alerts, the MDM pack, SSO, SIEM and "
            "S3 delivery, the LLM judge) can no longer be configured, and user/API-key/"
            f"ingest limits are reduced.\n\n{upgrade}\n")
    when = f"{days_left} day{'s' if days_left != 1 else ''}"
    if stage == "d7":
        return (
            f"Your 7-day AI exposure assessment for {org} is ready",
            f"A week into the Palivane trial for \"{org}\": here is what it saw.\n\n"
            + _assessment_lines(numbers, console)
            + f"The trial ends in {when}. After that, capture and detection keep running "
            "(a lapsed trial never stops protecting your fleet), but alerts, the MDM pack, "
            "SSO, SIEM/S3 delivery, and the LLM judge switch off, and user/API-key/ingest "
            f"limits tighten.\n\n{upgrade}\n\nIf Palivane isn't a fit, no action is needed — "
            "this is the halfway reminder.\n")
    return (
        f"Your Palivane trial for {org} ends in {when}",
        f"The Palivane trial for \"{org}\" ends in {when}.\n\n"
        "After that, capture and detection keep running (a lapsed trial never stops "
        "protecting your fleet), but alerts, the MDM pack, SSO, SIEM/S3 delivery, and the "
        "LLM judge switch off, and user/API-key/ingest limits tighten.\n\n"
        f"{upgrade}\n\nIf Palivane isn't a fit, no action is needed — this is the "
        f"{'last reminder before expiry' if stage == 'd2' else 'halfway reminder'}.\n")


def _admin_emails(db: Session, tenant_id: int) -> list[str]:
    rows = (db.query(User.email)
            .filter(User.tenant_id == tenant_id, User.role == "admin",
                    User.active.is_(True), User.email_verified.is_(True)).all())
    return [r[0] for r in rows]


def run_notices(db: Session, now: datetime | None = None) -> int:
    """Send every due trial notice. Returns how many tenants were notified."""
    if not email_mod.enabled():
        return 0
    now = now or _now()
    sent = 0
    tenants = (db.query(Tenant)
               .filter(Tenant.plan == "trial", Tenant.trial_ends_at.isnot(None),
                       Tenant.status == "active").all())
    for t in tenants:
        stage = due_stage(t, now)
        already = t.trial_notice or ""
        if _RANK[stage] <= _RANK.get(already, 0):
            continue
        # Claim before sending (conditional on the value we read), so a second worker
        # on the same tick loses the update and skips.
        claimed = (db.query(Tenant)
                   .filter(Tenant.id == t.id, Tenant.trial_notice == already)
                   .update({Tenant.trial_notice: stage}, synchronize_session=False))
        db.commit()
        if not claimed:
            continue
        days_left = max(0, (t.trial_ends_at - now).days + (1 if (t.trial_ends_at - now).seconds else 0))
        numbers = _assessment(db, t.id) if stage == "d7" else None
        subject, body = _compose(stage, t, days_left, numbers)
        recipients = _admin_emails(db, t.id)
        for to in recipients:
            email_mod.send(to, subject, body)
        if recipients:
            sent += 1
            log.info("trial notice %s sent for tenant %s (%d admin(s))",
                     stage, t.slug, len(recipients))
    return sent
