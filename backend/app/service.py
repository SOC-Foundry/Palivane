"""Shared analysis service: run the engine over an item and persist the finding.

Both the HTTP API and the ingestion poller funnel through `run_analysis`, so an
email pulled from a mailbox is stored identically to one submitted via the API.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .config import settings
from .detectors import AnalysisInput
from .engine import engine
from .models import Finding, Tenant
from .crypto import seal
from .redaction import redact_text


def _stored_content(content: str) -> str:
    """Redact secrets/PII (if enabled), then encrypt at rest (if enabled), for storage."""
    out = redact_text(content) if settings.redact_findings else content
    return seal(out) if settings.encrypt_findings else out


_ALLOW_LEVEL = {"benign", "low"}  # verdicts below the warn threshold


def run_analysis(item: AnalysisInput, persist: bool, db: Session,
                 tenant_id: int | None = None, signal_filter=None,
                 persist_benign: bool = True) -> dict:
    """Analyze one item, optionally persist a Finding, return the API payload.

    `tenant_id` attributes the stored finding to an organization (data isolation).
    `signal_filter` (list[Signal] -> list[Signal]) lets a per-tool policy drop expected
    categories before scoring (e.g. source code from a sanctioned coding assistant).
    `persist_benign=False` skips storing allow-level (benign/low) verdicts — used for
    high-volume sensor capture where benign tool calls are noise, not findings."""
    # A tenant can opt out of the LLM judge (it ships content to the judge provider).
    tenant = db.get(Tenant, tenant_id) if tenant_id is not None else None
    include_judge = not (tenant is not None and tenant.judge_enabled is False)
    verdict = engine.analyze(item, include_judge=include_judge)
    if signal_filter is not None:
        from .scoring import score
        verdict = score(signal_filter(list(verdict.signals)))
    result = verdict.to_dict()
    finding_id = None
    if persist and not persist_benign and verdict.severity in _ALLOW_LEVEL:
        persist = False  # drop benign sensor noise
    if persist:
        finding = Finding(
            tenant_id=tenant_id,
            channel=item.channel,
            surface=item.surface.value,
            sender=item.sender,
            subject=item.subject,
            content=_stored_content(item.content),
            risk_score=verdict.risk_score,
            severity=verdict.severity,
            recommended_action=verdict.recommended_action,
            ai_generated=verdict.ai_generated,
            attack_intent=verdict.attack_intent,
            signals=result["signals"],
            judge_used=engine.judge_enabled,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        finding_id = finding.id
        # Fire an alert (non-blocking) if the tenant configured a webhook.
        if tenant is not None and (tenant.alert_webhook or "").strip():
            from . import alerts
            alerts.notify(tenant.alert_webhook.strip(), tenant.alert_min_severity,
                          {**result, "finding_id": finding_id},
                          subject=item.subject, actor=item.sender, surface=item.surface.value,
                          digest=tenant.alert_digest or "off")
    return {"finding_id": finding_id, "judge_used": engine.judge_enabled, **result}
