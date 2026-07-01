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
from .redaction import redact_text


def run_analysis(item: AnalysisInput, persist: bool, db: Session,
                 tenant_id: int | None = None, signal_filter=None) -> dict:
    """Analyze one item, optionally persist a Finding, return the API payload.

    `tenant_id` attributes the stored finding to an organization (data isolation).
    `signal_filter` (list[Signal] -> list[Signal]) lets a per-tool policy drop expected
    categories before scoring (e.g. source code from a sanctioned coding assistant)."""
    # A tenant can opt out of the Claude judge (it ships content to Anthropic).
    include_judge = True
    if tenant_id is not None:
        tenant = db.get(Tenant, tenant_id)
        if tenant is not None and tenant.judge_enabled is False:
            include_judge = False
    verdict = engine.analyze(item, include_judge=include_judge)
    if signal_filter is not None:
        from .scoring import score
        verdict = score(signal_filter(list(verdict.signals)))
    result = verdict.to_dict()
    finding_id = None
    if persist:
        finding = Finding(
            tenant_id=tenant_id,
            channel=item.channel,
            surface=item.surface.value,
            sender=item.sender,
            subject=item.subject,
            content=redact_text(item.content) if settings.redact_findings else item.content,
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
    return {"finding_id": finding_id, "judge_used": engine.judge_enabled, **result}
