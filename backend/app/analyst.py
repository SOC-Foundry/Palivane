"""Palivane analyst agent — read-only finding investigation.

Given a finding, gather its context (its own signals/evidence and the same actor's other
recent findings) and have the configured LLM produce a structured investigation: what
happened, how serious, related activity, and a RECOMMENDED action with rationale.

Read-only by contract: it investigates and recommends, it never mutates a finding. Acting on
a recommendation is a separate, approval-gated step — deliberately so, because Palivane's own
`unsafe_autonomy` detector flags coding agents set to act without confirmation, and this agent
must be governed the way we tell customers to govern theirs.

Identity/providers mirror the LLM judge exactly: the operator's configured providers, or a
tenant's BYOK key. It sends the redacted finding context (to_summary — evidence snippets, not
raw decrypted content), the same data-sharing posture enabling the judge already accepts.
"""
from __future__ import annotations

import json

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .models import Finding

_PEER_LIMIT = 8         # same-actor findings for pattern context; bounds tokens
_ACTIONS = "dismiss | monitor | triage | quarantine | block"

_SYSTEM = (
    "You are a senior AI-security analyst working a finding in Palivane, an AI-security "
    "gateway. You are given one finding and the same actor's other recent findings, as "
    "structured JSON (categories, severity, surface, evidence snippets, timestamps).\n\n"
    "Investigate and RECOMMEND — you do not take the action yourself; a human applies it. "
    "Judge the real risk, not the raw severity: a confirmed secret or PII leak to an external "
    "AI tool is serious; a generic code paste or a documentation example is usually not. Use "
    "the actor's other findings to spot a pattern (repeat leaker, escalating behavior) versus "
    "a one-off. Be concise and calibrated. `recommended_action` must be one of: "
    f"{_ACTIONS}. Return the structured report."
)


class InvestigationReport(BaseModel):
    summary: str = Field(description="1-3 sentence analyst summary of what this finding is")
    assessment: str = Field(description="plain-language severity/impact assessment")
    related_activity: str = Field(
        description="patterns across the actor's other findings, or 'none observed'")
    recommended_action: str = Field(description=f"one of: {_ACTIONS}")
    rationale: str = Field(description="why that action, in one or two sentences")
    confidence: float = Field(ge=0.0, le=1.0, description="0..1 confidence in the recommendation")


def _context(db: Session, tenant_id: int, finding_id: int):
    """(finding_summary, peer_summaries) or None if the finding isn't this tenant's. Uses
    to_summary() — redacted evidence, never raw decrypted content."""
    row = db.get(Finding, finding_id)
    if not row or row.tenant_id != tenant_id:
        return None
    peers = []
    if row.sender:
        peers = [f.to_summary() for f in (
            db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.sender == row.sender,
                    Finding.id != row.id)
            .order_by(Finding.last_seen.desc().nullslast(), Finding.id.desc())
            .limit(_PEER_LIMIT).all())]
    return row.to_summary(), peers


def investigate(engine, db: Session, tenant_id: int, finding_id: int,
                judge_backends=None) -> dict | None:
    """Run the read-only investigation. Returns the report dict, None if no LLM provider is
    available (caller surfaces that), or raises LookupError if the finding isn't the tenant's."""
    ctx = _context(db, tenant_id, finding_id)
    if ctx is None:
        raise LookupError("finding not found")
    finding, peers = ctx

    judge = engine.judge
    use = judge_backends if judge_backends is not None else judge._backends
    if not use:
        return None   # no provider configured / tenant opted out — caller returns a clear 400

    user = (
        "FINDING UNDER REVIEW:\n" + json.dumps(finding, default=str)[:6000]
        + "\n\nSAME ACTOR — OTHER RECENT FINDINGS:\n"
        + (json.dumps(peers, default=str)[:3000] if peers else "(none)")
    )
    report, label = judge._run_with_failover(
        _SYSTEM, user, backends=judge_backends, output_format=InvestigationReport)
    if report is None:
        return None
    out = report.model_dump()
    out["by"] = label            # which provider produced it
    out["finding_id"] = finding_id
    return out
