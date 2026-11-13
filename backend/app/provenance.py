"""Instruction provenance: where an agent's instruction came from.

Every product scans the prompt. Nobody tracks that the text telling the agent to "curl this
and run it" arrived in a tool result, a fetched page, a file, or a message from another
agent, which nobody typed. Palivane sees both halves: the content coming IN to the agent
(a gateway request's latest tool_result, an inference hook's tool_result, an A2A message)
and the actions going OUT (a tools/call on the mcp and agent_tools surfaces).

When inbound content carries instruction-shaped threats (prompt injection, a jailbreak, an
exfiltration instruction: the manipulation stage), the actor is TAINTED for a while: a
row naming the source. An action by that actor inside the window that reaches a payoff
stage (collection, execution, exfiltration) gets one more signal, "acting on an
instruction nobody typed", naming the source and the finding that carried it. It scores
as a strong prompt-injection link, so the verdict rises and the chain gets its manipulation
stage with provenance attached, rather than a regex match on a page someone fetched.

Only inbound surfaces taint. A person's own prompt carrying an injection phrase is what the
per-event finding already says; it does not make their next command tainted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .detectors.base import AnalysisInput, Category, Signal
from .models import InstructionTaint
from .session_correlation import _LATE_STAGES, stages_in

WINDOW = timedelta(minutes=30)
_INBOUND_METHODS = {"tool_result", "tools/list.result", "tools/advertised"}
_MANIPULATION = {"prompt_injection", "jailbreak", "data_exfiltration", "tool_poisoning"}
_ACTION_SURFACES = {"mcp", "agent_tools"}
CHECK = "instruction_provenance"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _cat(s) -> str:
    c = s.get("category") if isinstance(s, dict) else getattr(s, "category", "")
    return getattr(c, "value", c) or ""


def inbound_source(item: AnalysisInput) -> str:
    """What this event is, if it is content arriving at an agent from somewhere untrusted:
    a tool's result, advertised tool descriptions, or another agent's message. "" when it
    is the actor's own action or prompt."""
    md = item.metadata or {}
    surface = getattr(item.surface, "value", item.surface)
    if surface == "a2a":
        frm = md.get("from_agent") or "another agent"
        return f"a message from agent {frm}"
    method = md.get("method") or ""
    if method in _INBOUND_METHODS:
        tool = md.get("tool") or item.channel or ""
        return f"the result of {tool}" if tool else "a tool result"
    return ""


def remember(db: Session, tenant_id: int | None, item: AnalysisInput, signals, finding_id) -> bool:
    """After an inbound event is scored: taint the actor when it carried instruction-shaped
    threats. Best-effort; never raises into the capture path."""
    if tenant_id is None or db is None or not item.sender:
        return False
    source = inbound_source(item)
    if not source or not any(_cat(s) in _MANIPULATION for s in signals or []):
        return False
    try:
        now = _now()
        db.add(InstructionTaint(tenant_id=tenant_id, actor=item.sender.strip().lower(),
                                source=source[:320], finding_id=finding_id,
                                created_at=now, expires_at=now + WINDOW))
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def active(db: Session, tenant_id: int, actor: str, now: datetime | None = None):
    now = now or _now()
    return (db.query(InstructionTaint)
              .filter(InstructionTaint.tenant_id == tenant_id,
                      InstructionTaint.actor == (actor or "").strip().lower(),
                      InstructionTaint.expires_at > now)
              .order_by(InstructionTaint.created_at.desc()).first())


def signal_for(db: Session, tenant_id: int | None, item: AnalysisInput, signals) -> Signal | None:
    """The provenance signal for an action, or None: the actor is tainted, this is an action
    (not inbound content), and the action reaches a payoff stage on its own."""
    if tenant_id is None or db is None or not item.sender:
        return None
    surface = getattr(item.surface, "value", item.surface)
    if surface not in _ACTION_SURFACES or inbound_source(item):
        return None
    if not (stages_in(signals) & _LATE_STAGES):
        return None
    try:
        taint = active(db, tenant_id, item.sender)
    except Exception:
        return None
    if taint is None:
        return None
    ago = max(0, int((_now() - taint.created_at).total_seconds() // 60)) if taint.created_at else 0
    stage = ", ".join(sorted(stages_in(signals) & _LATE_STAGES))
    ref = f" (finding #{taint.finding_id})" if taint.finding_id else ""
    return Signal(
        category=Category.PROMPT_INJECTION,
        title="Acting on an instruction nobody typed",
        detail=(f"{taint.source} carried instructions to this agent {ago} minute(s) ago{ref}; "
                f"this {stage} action followed. The instruction's source, not the person, is "
                "what this action answers to."),
        weight=0.85, confidence=0.8, detector="provenance",
        evidence=taint.source[:120], check=CHECK)
