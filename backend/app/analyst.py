"""Palivane analyst agent — read-only finding investigation.

Given a finding, gather its context (its own signals/evidence and the same actor's other
recent findings) and have the configured LLM produce a structured investigation: what
happened, how serious, related activity, and a RECOMMENDED action with rationale.

Read-only by contract: it investigates and recommends, it never mutates a finding. Acting on
a recommendation is a separate, approval-gated step — deliberately so, because Palivane's own
`unsafe_autonomy` detector flags coding agents set to act without confirmation, and this agent
must be governed the way we tell customers to govern theirs.

Providers: the tenant's OWN key (BYOK) and nothing else. The judge may fall back to the
operator's global providers because that is disclosed and opt-out-able; the analyst may not,
because an admin pressing Investigate is told the context goes to *their* provider — see
service.resolve_analyst_backends. It sends the redacted finding context (to_summary — evidence
snippets, not raw decrypted content), never to a model vendor of Palivane's.
"""
from __future__ import annotations

import json

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .models import Finding

_PEER_LIMIT = 8         # same-actor findings for pattern context; bounds tokens
# Finding-native actions, so the recommendation maps 1:1 to what a human can apply to a
# recorded finding: dismiss (benign / accepted), triage (real, being handled), keep_open
# (undecided, leave for review). Enforcement verbs (quarantine/block) are policy decisions,
# not actions on a past finding, so they are deliberately not offered here.
_ACTIONS = "dismiss | triage | keep_open"

_SYSTEM = (
    "You are a senior AI-security analyst working a finding in Palivane, an AI-security "
    "gateway. You are given one finding and the same actor's other recent findings, as "
    "structured JSON (categories, severity, surface, evidence snippets, timestamps).\n\n"
    "Investigate and RECOMMEND — you do not take the action yourself; a human applies it. "
    "Judge the real risk, not the raw severity: a confirmed secret or PII leak to an external "
    "AI tool is serious; a generic code paste or a documentation example is usually not. Use "
    "the actor's other findings to spot a pattern (repeat leaker, escalating behavior) versus "
    "a one-off. Be concise and calibrated. `recommended_action` must be one of: "
    f"{_ACTIONS} — dismiss a benign/false-positive or accepted finding, triage one that is "
    "real and needs handling, keep_open when it's genuinely undecided. Return the report."
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
    to_summary() — redacted evidence, never raw decrypted content. Evidence is label-only for
    secrets/PII/PHI (the detectors emit the pattern's name, not its match) and truncated for
    the entropy heuristic, so what leaves names the kind of thing found, not the thing."""
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


_REDACTED = "[redacted]"


def _redact(summary):
    """A copy of a finding summary with the actor's email (`sender`) and the message `subject`
    masked before it leaves to the LLM provider. These are identifiers, not evidence: the
    analyst correlates peers by actor internally (they are the same sender by construction) and
    the 'SAME ACTOR' framing carries that, so the provider never needs the address or subject."""
    if not isinstance(summary, dict):
        return summary
    out = dict(summary)
    if out.get("sender"):
        out["sender"] = _REDACTED
    if out.get("subject"):
        out["subject"] = _REDACTED
    return out


def investigate(engine, db: Session, tenant_id: int, finding_id: int,
                judge_backends=None) -> dict | None:
    """Run the read-only investigation. Returns the report dict, None if no LLM provider is
    available (caller surfaces that), or raises LookupError if the finding isn't the tenant's."""
    ctx = _context(db, tenant_id, finding_id)
    if ctx is None:
        raise LookupError("finding not found")
    finding, peers = ctx
    finding = _redact(finding)                 # sender/subject never leave to the provider
    peers = [_redact(p) for p in peers]

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
