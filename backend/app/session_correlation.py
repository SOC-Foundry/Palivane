"""Session behavioral correlation — attack chains across an actor's recent activity.

Every other detector scores ONE event: this prompt, this tool call, this file. But the
dangerous pattern is a *sequence* — an agent reads credentials, then runs a shell command,
then sends data out. Each step can look benign or sub-block on its own; together they are
the Nx-s1ngularity shape. This module runs after a finding is stored, looks back over the
same actor's recent findings, maps each to a kill-chain STAGE, and — when the window holds
an escalating cross-stage chain — records ONE correlated finding that scores the *pattern*,
not the step.

There is no explicit session id in the ingest stream, so the correlation key is
(tenant, actor): a rolling `PALIVANE_SESSION_WINDOW_MIN`-minute window of that actor's
activity. Cheap: one indexed lookback query (ix_findings_tenant_last_seen) per
chain-relevant event, bounded and read-only except for the single correlated row.

Dedup: the correlated finding's fingerprint is keyed on (tenant, actor, sorted stage-set),
so while the same chain persists in the window it folds via the existing recurrence
mechanism instead of re-firing; when a NEW stage joins (the chain escalates) the
fingerprint changes and a fresh, higher-severity correlated finding fires — which is the
signal you want.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from . import config          # read config.settings.* (not a captured ref) so a config
                             # reload — e.g. in tests — is respected, not stale-bound
from .models import Finding, Tenant

# Kill-chain stages, early → late. A category maps to at most one stage. "Early" stages set
# up an attack (find the target, subvert the agent); "late" stages are the payoff (take the
# data, run the command, send it out) — a chain that crosses from early to late, or spans
# three+ stages, is the correlation signal.
_STAGE_ORDER = ["recon", "manipulation", "collection", "execution", "exfiltration"]
_LATE_STAGES = {"collection", "execution", "exfiltration"}

_CATEGORY_STAGE = {
    # recon — locating/opening sensitive material
    "sensitive_resource_access": "recon",
    "credential_at_rest": "recon",
    # manipulation — subverting the agent or its guardrails
    "prompt_injection": "manipulation",
    "jailbreak": "manipulation",
    "tool_poisoning": "manipulation",
    "unsafe_autonomy": "manipulation",
    "agent_authz": "manipulation",
    "mcp_untrusted_server": "manipulation",
    "mcp_integrity": "manipulation",
    # collection — gathering the secrets/data itself
    "secret_leak": "collection",
    "pii_exposure": "collection",
    "phi_exposure": "collection",
    "source_code_leak": "collection",
    "confidential_data": "collection",
    "data_oversharing": "collection",
    # execution — running something on the host
    "dangerous_command": "execution",
    # exfiltration — data leaving for somewhere it shouldn't
    "data_exfiltration": "exfiltration",
    "unsanctioned_ai": "exfiltration",
}
# Categories that never contribute to a chain (authorship noise, and correlation's own output).
_IGNORED = {"ai_generated", "session_correlation"}


def stages_in(signals) -> set[str]:
    """The distinct kill-chain stages present in a finding's signal list."""
    out: set[str] = set()
    for s in signals or []:
        cat = (s.get("category") if isinstance(s, dict) else getattr(s, "category", "")) or ""
        cat = getattr(cat, "value", cat)
        stage = _CATEGORY_STAGE.get(cat)
        if stage:
            out.add(stage)
    return out


def is_chain_relevant(signals) -> bool:
    """Worth a lookback? Only if the just-stored finding itself touches a chain stage —
    benign/authorship-only events don't trigger the (cheap, but non-zero) correlation query."""
    return bool(stages_in(signals))


def _severity_for(stages: set[str]) -> tuple[str, int]:
    """Correlated severity/score from the chain's shape. Reaching a payoff stage
    (exfiltration or execution) alongside anything else is the worst; a broad multi-stage
    chain is next; setup-plus-collection is high."""
    if "exfiltration" in stages:
        return "critical", 95           # data left for somewhere it shouldn't
    if "execution" in stages:
        return "critical", 90           # ran something on the host
    if len(stages) >= 3:
        return "critical", 92
    return "high", 82                   # e.g. recon → collection (setup + grab)


def _should_correlate(stages: set[str]) -> bool:
    """Fire when the window holds 2+ distinct stages AND at least one is a LATE (payoff)
    stage — collection, execution, or exfiltration. That captures the canonical chains:
    read-secrets → send-them-out (collection+exfiltration, often with no separate recon
    event), and recon → collection. Pure setup (recon+manipulation, no payoff) doesn't
    fire, and a single stage repeated is the per-event detectors' job, not a chain."""
    if len(stages) < 2:
        return False
    return bool(stages & _LATE_STAGES) or len(stages) >= 3


def _fingerprint(tenant_id, actor: str, stages: set[str]) -> str:
    key = f"{tenant_id}|{actor}|session|{'+'.join(sorted(stages))}"
    return hashlib.sha256(key.encode()).hexdigest()[:64]


def _order(stages: set[str]) -> list[str]:
    return [s for s in _STAGE_ORDER if s in stages]


def correlate(db: Session, tenant_id: int | None, actor: str, agent: str = "",
              dispatch=None) -> int | None:
    """Look across the actor's recent findings for an escalating attack chain; if present,
    record a single correlated finding (folding on its stage-signature). Returns the
    finding id when one is written/folded, else None. `dispatch(tenant, payload, subject,
    actor, surface)` fires alerts/SIEM for a freshly-written correlated finding.

    Read-only apart from the one correlated row. Runs inside the caller's request session,
    so RLS (app.tenant_id GUC) already scopes the lookback to this tenant."""
    if not config.settings.session_correlation or tenant_id is None or not actor:
        return None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    since = now - timedelta(minutes=max(1, config.settings.session_window_min))

    recent = (db.query(Finding)
              .filter(Finding.tenant_id == tenant_id,
                      Finding.sender == actor,
                      Finding.last_seen >= since)
              .order_by(Finding.last_seen.desc())
              .limit(300).all())

    stages: set[str] = set()
    contributing: list[int] = []
    for f in recent:
        st = stages_in(f.signals)
        if st:
            stages |= st
            contributing.append(f.id)
    # Correlation is about a SEQUENCE: the chain must span ≥2 distinct events. A single
    # event that itself carries two categories (a secret plus an exfil destination) is
    # already flagged on its own — it is not a cross-event chain.
    if len(contributing) < 2 or not _should_correlate(stages):
        return None

    severity, score = _severity_for(stages)
    fp = _fingerprint(tenant_id, actor, stages)

    # Fold: same stage-signature already recorded this window → bump, don't duplicate.
    prior = (db.query(Finding)
             .filter(Finding.tenant_id == tenant_id, Finding.fingerprint == fp,
                     Finding.status != "dismissed")
             .order_by(Finding.id.desc()).first())
    if prior is not None:
        prior.seen_count = (prior.seen_count or 1) + 1
        prior.last_seen = now
        db.commit()
        return prior.id

    ordered = _order(stages)
    signal = {
        "category": "session_correlation",
        "title": "Correlated attack chain across recent activity",
        "detail": (f"{actor} strung together {len(stages)} kill-chain stages within "
                   f"{config.settings.session_window_min}m: {' → '.join(ordered)}. Individually "
                   "these actions may look benign or low-risk; in sequence they match an "
                   "agent-compromise pattern (setup → collection → exfiltration)."),
        "weight": 0.95, "confidence": 0.9, "detector": "session_correlation",
        "evidence": " → ".join(ordered), "check": "session_chain",
    }
    finding = Finding(
        tenant_id=tenant_id, fingerprint=fp,
        channel="session", surface="session",
        sender=actor, agent=agent or "",
        subject=f"attack chain: {' → '.join(ordered)}",
        content="", risk_score=score, severity=severity,
        recommended_action="block", ai_generated=False, attack_intent=True,
        signals=[signal], judge_used=False,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    if dispatch is not None:
        payload = {"risk_score": score, "severity": severity,
                   "recommended_action": "block", "signals": [signal],
                   "finding_id": finding.id}
        try:
            dispatch(db.get(Tenant, tenant_id), payload, finding.subject, actor, "session")
        except Exception:
            pass  # notification must never sink the correlation write
    return finding.id
