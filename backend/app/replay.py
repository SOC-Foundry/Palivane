"""The flight recorder: one actor's window as a scrubbable recording, and the same window
replayed against a policy that is not the one that was in force.

Every row exists already. Findings give the prompts, tool calls, responses and inbound
content with their signals and the verdict that was returned; the taint table gives where
an instruction came from; the exposure register gives what left; containments give when
the actor was stopped; attestations give the commits. `recording()` orders them into steps
with a scrubber index. `replay()` takes a proposed policy (block thresholds, enforce stance,
disabled checks, whether confirmed leaks force a block), rescores each step's stored signals
through the real scorer and says what the verdict would have been, so incident review and
policy tuning are one screen: "which step would this policy have stopped".

Replay re-scores what was recorded; it does not re-run the detectors. A check that was
switched off at the time left no signal and cannot be replayed on, which the result says.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .detectors.base import Category, Signal
from .models import CommitAttestation, Containment, ExposureRecord, Finding, InstructionTaint

_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}
MAX_STEPS = 2000


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse(ts: str | None, default: datetime) -> datetime:
    if not ts:
        return default
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        return default


def _kind(f: Finding, inbound: bool = False) -> str:
    md_dir = ""
    subj = (f.subject or "").lower()
    if f.surface == "session":
        return "chain"
    if "response" in subj:
        return "response"
    if inbound or "tool result" in subj or "tool_result" in subj or f.surface == "a2a":
        return "inbound"
    if f.surface in ("mcp", "agent_tools"):
        return "tool"
    if f.surface in ("ai_usage", "llm_io"):
        return "prompt" if not md_dir else "response"
    return f.surface or "event"


def _signals(f: Finding) -> list[dict]:
    out = []
    for s in f.signals or []:
        out.append({"category": s.get("category"), "check": s.get("check") or s.get("category"),
                    "title": s.get("title"), "evidence": (s.get("evidence") or "")[:160],
                    "weight": s.get("weight"), "confidence": s.get("confidence")})
    return out


def recording(db: Session, tenant_id: int, actor: str, since: str | None = None,
              until: str | None = None, days: int = 7) -> dict:
    actor = (actor or "").strip().lower()
    now = _now()
    t1 = _parse(until, now)
    t0 = _parse(since, t1 - timedelta(days=max(1, days)))
    rows = (db.query(Finding)
              .filter(Finding.tenant_id == tenant_id,
                      or_(func.lower(Finding.sender) == actor, func.lower(Finding.agent) == actor),
                      Finding.last_seen >= t0, Finding.last_seen <= t1)
              .order_by(Finding.last_seen.asc()).limit(MAX_STEPS).all())
    taints = {t.finding_id: t for t in db.query(InstructionTaint)
              .filter(InstructionTaint.tenant_id == tenant_id, InstructionTaint.actor == actor,
                      InstructionTaint.created_at >= t0 - timedelta(hours=1)).all()}
    exposures = {e.finding_id: e for e in db.query(ExposureRecord)
                 .filter(ExposureRecord.tenant_id == tenant_id, ExposureRecord.opened_at >= t0,
                         ExposureRecord.opened_at <= t1).all()}
    steps: list[dict] = []
    for f in rows:
        checks = {s.get("check") for s in (f.signals or [])}
        prov = next((s for s in (f.signals or []) if s.get("check") == "instruction_provenance"), None)
        inbound = f.id in taints or "canary_instruction_read" in checks
        steps.append({
            "t": (f.last_seen or f.created_at).isoformat(), "kind": _kind(f, inbound), "finding_id": f.id,
            "surface": f.surface, "channel": f.channel, "subject": f.subject,
            "severity": f.severity, "risk_score": f.risk_score or 0,
            "action": f.recommended_action or "allow", "status": f.status,
            "reviewed_by": f.reviewed_by or "", "seen_count": f.seen_count or 1,
            "signals": _signals(f),
            "tainted_source": (taints[f.id].source if f.id in taints else None),
            "acted_on_planted": bool(prov), "planted_source": (prov or {}).get("evidence", "")[:160] if prov else "",
            "canary": ("obeyed" if "canary_instruction_obeyed" in checks else "read" if "canary_instruction_read" in checks else ""),
            "exposure": ({"id": exposures[f.id].id, "classes": exposures[f.id].classes, "regime": exposures[f.id].regime,
                          "status": exposures[f.id].status} if f.id in exposures else None),
        })
    cons = (db.query(Containment)
              .filter(Containment.tenant_id == tenant_id, func.lower(Containment.target) == actor,
                      Containment.created_at >= t0, Containment.created_at <= t1 + timedelta(days=30)).all())
    for c in cons:
        if c.created_at and t0 <= c.created_at <= t1:
            steps.append({"t": c.created_at.isoformat(), "kind": "contain", "finding_id": None,
                          "subject": f"Contained by {c.created_by}: {c.reason or 'no reason given'}",
                          "severity": "critical", "action": "block", "signals": [], "containment_id": c.id,
                          "reverted": bool(c.revert_since)})
        if c.released_at and t0 <= c.released_at <= t1:
            steps.append({"t": c.released_at.isoformat(), "kind": "release", "finding_id": None,
                          "subject": f"Released by {c.released_by}", "severity": "benign", "action": "allow",
                          "signals": [], "containment_id": c.id})
    for a in (db.query(CommitAttestation)
                .filter(CommitAttestation.tenant_id == tenant_id, func.lower(CommitAttestation.actor) == actor,
                        CommitAttestation.created_at >= t0, CommitAttestation.created_at <= t1).all()):
        steps.append({"t": a.created_at.isoformat(), "kind": "commit", "finding_id": None,
                      "subject": f"{a.sha[:10]} {a.subject}".strip(), "severity": "benign", "action": "allow",
                      "signals": [], "sha": a.sha, "tool_calls": a.tool_calls, "files": a.files,
                      "blocked": a.blocked, "findings": a.findings})
    steps.sort(key=lambda s: s["t"])
    for i, s in enumerate(steps):
        s["i"] = i
    stopped = sum(1 for s in steps if s.get("action") == "block" and s["kind"] not in ("contain", "release"))
    return {"actor": actor, "from": t0.isoformat(), "to": t1.isoformat(), "steps": steps,
            "summary": {"steps": len(steps), "findings": sum(1 for s in steps if s.get("finding_id")),
                        "stopped": stopped, "exposures": sum(1 for s in steps if s.get("exposure")),
                        "planted": sum(1 for s in steps if s.get("acted_on_planted")),
                        "canary_obeyed": sum(1 for s in steps if s.get("canary") == "obeyed"),
                        "commits": sum(1 for s in steps if s["kind"] == "commit")}}


# --- replay against a policy -----------------------------------------------------------------

def _rebuild(signals: list[dict]) -> list[Signal]:
    out = []
    for s in signals:
        try:
            cat = Category(s.get("category"))
        except ValueError:
            continue
        out.append(Signal(category=cat, title=s.get("title") or "", detail="", weight=float(s.get("weight") or 0),
                          confidence=float(s.get("confidence") or 0), detector="replay",
                          evidence=s.get("evidence") or "", check=s.get("check") or ""))
    return out


def _action(severity: str, block_at: str) -> str:
    r = _RANK.get(severity, 0)
    if r >= _RANK.get(block_at, 3):
        return "block"
    return "warn" if r >= 2 else "allow"


def replay(rec: dict, policy: dict) -> dict:
    """Each finding step rescored under `policy`:
        block_severity      threshold for prompts/responses (default high)
        mcp_block_severity  threshold for tool calls (default high)
        enforce             whether a block is enforced or only recorded (default true)
        enforce_secrets     a confirmed credential/PII leak forces a block (default true)
        disabled_checks     checks dropped before scoring
    """
    from .detectors.shadow_ai import confirmed_leak
    from .scoring import score
    disabled = {str(c).strip() for c in (policy.get("disabled_checks") or []) if str(c).strip()}
    block_at = policy.get("block_severity") or "high"
    mcp_at = policy.get("mcp_block_severity") or block_at
    enforce = policy.get("enforce", True)
    enforce_secrets = policy.get("enforce_secrets", True)
    steps = []
    stopped_then = stopped_now = 0
    first_stop = None
    for s in rec["steps"]:
        if not s.get("finding_id"):
            steps.append({**s, "replayed_action": s.get("action"), "changed": False})
            continue
        kept = [x for x in s["signals"] if (x.get("check") or x.get("category")) not in disabled]
        sigs = _rebuild(kept)
        v = score(sigs) if sigs else None
        sev = v.severity if v else "benign"
        at = mcp_at if s["kind"] in ("tool", "inbound") else block_at
        act = _action(sev, at)
        force = bool(enforce_secrets and sigs and confirmed_leak(sigs))
        if force:
            act = "block"
        outcome = act if (enforce or force) else ("warn" if act == "block" else act)
        then = s.get("action") or "allow"
        # The scorer's vocabulary is allow / monitor / quarantine / block; the replay's is
        # allow / warn / block. quarantine and monitor are warnings, not stops.
        then_coarse = "block" if then == "block" else ("warn" if then in ("quarantine", "monitor", "warn") else "allow")
        then_stopped = then_coarse == "block"
        if then_stopped:
            stopped_then += 1
        if act == "block":
            stopped_now += 1
            if first_stop is None:
                first_stop = s["i"]
        steps.append({**s, "replayed_severity": sev, "replayed_action": act, "replayed_outcome": outcome,
                      "dropped_checks": sorted({(x.get("check") or x.get("category")) for x in s["signals"]} - {(x.get("check") or x.get("category")) for x in kept}),
                      "changed": act != then_coarse})
    return {"actor": rec["actor"], "from": rec["from"], "to": rec["to"], "policy": {
                "block_severity": block_at, "mcp_block_severity": mcp_at, "enforce": bool(enforce),
                "enforce_secrets": bool(enforce_secrets), "disabled_checks": sorted(disabled)},
            "steps": steps,
            "summary": {"stopped_then": stopped_then, "stopped_now": stopped_now,
                        "changed": sum(1 for s in steps if s.get("changed")), "first_stop": first_stop,
                        "note": "Replay rescores what was recorded. A check that was off at the time left no signal and cannot be replayed on."}}
