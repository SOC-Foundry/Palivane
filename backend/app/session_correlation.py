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

from sqlalchemy import or_
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
    # NOT unsanctioned_ai. It describes the DESTINATION, not an action in a sequence, and it
    # fires on every prompt to any tool the org has not sanctioned — which on a fresh tenant
    # is all of them. Mapped to a payoff stage it turned every sensitive prompt into a
    # two-stage "collection → exfiltration" chain scored critical, so the correlated finding
    # stopped meaning "I saw an attack pattern" and started meaning "you typed something
    # sensitive into an AI tool" — which the underlying finding already said, at the right
    # severity. Real egress still reaches this stage through data_exfiltration.
}
# A secret IN a prompt carries the data_exfiltration category, but it is the secret itself:
# collection, not something leaving. (The exfiltration-phrase check stays exfiltration: an
# instruction to send data out is the payoff an injected agent acts on. What stops one person
# talking about security from becoming a "collection → exfiltration" chain, as seen in prod on
# 2026-11-09, is the agent-action rule below, not this map.) Keyed on detector and title.
_SIGNAL_STAGE = {
    ("prompt_threats", "Credential/secret present in LLM I/O"): "collection",
}

# A chain is an AGENT's sequence: a tool or MCP call is what turns "read the secrets" into
# "did something with them". A person's own prompts can be links in an agent's chain (the
# injected instruction, the pasted key), but on their own they are what the per-event
# findings already say. So a chain needs at least one finding from an agent's actions.
_AGENT_SURFACES = {"mcp", "agent_tools", "a2a"}

# Categories that never contribute to a chain (authorship noise, and correlation's own output).
_IGNORED = {"ai_generated", "session_correlation"}


# Below this strength (weight x confidence) a signal is a HINT, not an event, and cannot be a
# link in a chain. The module exists to catch a sequence of events that are each sub-block;
# it was being fed by guesses. The warn-level entropy token is 0.49, "patient record" 0.49,
# "personal record" 0.41, the ML code/injection classifiers 0.34-0.4, while a known-format
# secret is 0.77, a dashed SSN 0.6, a dangerous command 0.86, a sensitive path 0.81. On one
# developer's own traffic the hints chained into six block-recommended "attack chains", one of
# them 50 recurrences deep. Each hint is still its own finding; it just no longer vouches for a
# stranger. A signal stored without a weight (older rows) counts: absence is not weakness.
_MIN_LINK_STRENGTH = 0.5

# A chain also needs an ANCHOR: one contributing finding whose link is evidence on its own.
# Measured on the real engine: a known-format secret is 0.77, a sensitive path 0.81, a
# dashed SSN leaving for an AI tool 0.6, a poisoned agent message 0.62; a dangerous-command
# phrase in chat is 0.56 and an exfil phrase 0.52. The last two are links, in two stages,
# one a payoff, so the stage logic reads them as a sequence; but each is a guess, and a
# chain of guesses is a guess with a critical badge. They can still be links; one of them
# cannot be the only thing holding the chain up.
_MIN_ANCHOR_STRENGTH = 0.6


def _strength(sig) -> float | None:
    w = sig.get("weight") if isinstance(sig, dict) else getattr(sig, "weight", None)
    c = sig.get("confidence") if isinstance(sig, dict) else getattr(sig, "confidence", None)
    if w is None or c is None:
        return None
    return w * c


def _is_link(sig) -> bool:
    st = _strength(sig)
    return True if st is None else st >= _MIN_LINK_STRENGTH


def has_anchor(signals) -> bool:
    """Whether a finding carries a link strong enough to anchor a chain on its own. A
    signal stored without a weight (older rows) counts, as for links."""
    for s in signals or []:
        cat = (s.get("category") if isinstance(s, dict) else getattr(s, "category", "")) or ""
        if getattr(cat, "value", cat) in _IGNORED:
            continue
        st = _strength(s)
        if st is None or st >= _MIN_ANCHOR_STRENGTH:
            return True
    return False


def stages_in(signals) -> set[str]:
    """The distinct kill-chain stages present in a finding's signal list. Hint-strength
    signals (see `_MIN_LINK_STRENGTH`) do not count."""
    out: set[str] = set()
    for s in signals or []:
        if not _is_link(s):
            continue
        cat = (s.get("category") if isinstance(s, dict) else getattr(s, "category", "")) or ""
        cat = getattr(cat, "value", cat)
        det = (s.get("detector") if isinstance(s, dict) else getattr(s, "detector", "")) or ""
        title = (s.get("title") if isinstance(s, dict) else getattr(s, "title", "")) or ""
        stage = _SIGNAL_STAGE.get((det, title)) or _CATEGORY_STAGE.get(cat)
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


def _chain_of(findings) -> tuple[set[str], list[int]]:
    """The chain a list of one actor's findings makes: its stages and the ids of the
    findings that contribute, or (set(), []) when they make no chain.

    Correlation is about a SEQUENCE: the chain must span 2+ distinct events, one of them an
    agent's action (a person's chat prompts alone are not a chain), with 2+ stages one of
    which is a payoff stage, and at least one anchor (see `_MIN_ANCHOR_STRENGTH`). A single
    event that itself carries two categories (a secret plus an exfil destination) is already
    flagged on its own; it is not a cross-event chain."""
    stages: set[str] = set()
    contributing: list[int] = []
    agent_acted = anchored = False
    for f in findings:
        st = stages_in(f.signals)
        if st:
            stages |= st
            contributing.append(f.id)
            agent_acted = agent_acted or (f.surface in _AGENT_SURFACES)
            anchored = anchored or has_anchor(f.signals)
    if len(contributing) < 2 or not agent_acted or not anchored or not _should_correlate(stages):
        return set(), []
    return stages, contributing


def _with_contributing(origin, ids) -> dict:
    prior = origin.get("contributing") if isinstance(origin, dict) else None
    merged = sorted(set(prior or []) | set(ids))
    return {**(origin if isinstance(origin, dict) else {}), "contributing": merged}


def reconcile_chains(db: Session, tenant_id: int | None, finding_ids, by: str = "",
                     reason: str = "") -> list[int]:
    """After findings are dismissed: re-derive every open chain they were part of from the
    findings that are still standing, and dismiss the chain if it no longer holds.

    A chain is only ever as good as its links. When a person judged the links false
    positives, the "attack chain" built on them stayed open, critical, at the top of the
    queue (prod #1426/#1431, 2026-11-12: 19 findings dismissed, two chains left). The chain
    inherits the review: dismissed, by the same person, for the same reason (the detector
    was wrong because its inputs were), via `bulk`, since nobody looked at the chain itself.

    Returns the ids of the chains dismissed. The caller audits and commits."""
    from . import review
    ids = {int(i) for i in (finding_ids or [])}
    if tenant_id is None or not ids:
        return []
    inputs = (db.query(Finding.id, Finding.sender)
                .filter(Finding.tenant_id == tenant_id, Finding.id.in_(ids)).all())
    actors = {sender for _, sender in inputs if sender}
    if not actors:
        return []
    chains = (db.query(Finding)
                .filter(Finding.tenant_id == tenant_id, Finding.surface == "session",
                        Finding.sender.in_(actors),
                        or_(Finding.status.is_(None), Finding.status != "dismissed"))
                .all())
    window = timedelta(minutes=max(1, config.settings.session_window_min))
    dismissed: list[int] = []
    for chain in chains:
        listed = (chain.origin or {}).get("contributing") if isinstance(chain.origin, dict) else None
        if listed and not (set(listed) & ids):
            continue                       # built from other findings; this review is not about it
        anchor_t = chain.last_seen or chain.created_at or datetime.now(timezone.utc).replace(tzinfo=None)
        standing = (db.query(Finding)
                      .filter(Finding.tenant_id == tenant_id, Finding.sender == chain.sender,
                              Finding.surface != "session",
                              Finding.last_seen >= anchor_t - window,
                              Finding.last_seen <= anchor_t + window,
                              or_(Finding.status.is_(None), Finding.status != "dismissed"))
                      .order_by(Finding.last_seen.desc()).limit(300).all())
        stages, contributing = _chain_of(standing)
        if stages and _fingerprint(tenant_id, chain.sender, stages) == chain.fingerprint:
            # Still holds on what is left: the list is what is left, not what it was.
            chain.origin = {**(chain.origin if isinstance(chain.origin, dict) else {}),
                            "contributing": sorted(contributing)}
            db.commit()
            continue
        review.record_review(chain, "dismissed", by, "bulk",
                             reason if reason in review.REASONS else "false_positive")
        chain.status = "dismissed"
        dismissed.append(chain.id)
    if dismissed:
        db.commit()
    return dismissed


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

    # A finding a human has dismissed is not part of anyone's story. Without this filter,
    # triaging the noise did not make the "attack chain" built on it go away.
    recent = (db.query(Finding)
              .filter(Finding.tenant_id == tenant_id,
                      Finding.sender == actor,
                      Finding.last_seen >= since,
                      or_(Finding.status.is_(None), Finding.status != "dismissed"))
              .order_by(Finding.last_seen.desc())
              .limit(300).all())

    stages, contributing = _chain_of(recent)
    if not stages:
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
        prior.origin = _with_contributing(prior.origin, contributing)
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
        # Which findings this chain is made of, so a review of them reaches it
        # (reconcile_chains) and the console can show the links.
        origin={"contributing": sorted(contributing)},
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
