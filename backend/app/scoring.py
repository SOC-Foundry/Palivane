"""Fuse signals from all detectors into a single risk verdict.

Design goals:
- A lone weak signal shouldn't raise much alarm.
- The *combination* of "AI-generated" + "attack intent" should escalate sharply —
  that pairing is the core threat this platform hunts.
- Score saturates (probabilistic OR) so many small signals can't trivially max it,
  but several strong ones reliably do.
"""

from __future__ import annotations

from dataclasses import dataclass

from .detectors.base import Category, Signal


@dataclass
class Verdict:
    risk_score: int           # 0..100
    severity: str             # benign | low | suspicious | high | critical
    recommended_action: str   # allow | monitor | quarantine | block
    ai_generated: bool
    attack_intent: bool
    signals: list[Signal]

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "ai_generated": self.ai_generated,
            "attack_intent": self.attack_intent,
            "signals": [
                {
                    "category": s.category.value,
                    "title": s.title,
                    "detail": s.detail,
                    "weight": round(s.weight, 3),
                    "confidence": round(s.confidence, 3),
                    "detector": s.detector,
                    "evidence": s.evidence,
                    "check": s.effective_check,
                }
                for s in self.signals
            ],
        }


_AI_CATEGORIES = {Category.AI_GENERATED}
_ATTACK_CATEGORIES = {
    # Protect our AI — an injection/jailbreak/exfil attempt is itself the attack.
    Category.PROMPT_INJECTION,
    Category.JAILBREAK,
    Category.DATA_EXFILTRATION,
    # Shadow-AI governance — sensitive data leaving for an AI tool is the risk.
    Category.SECRET_LEAK,
    Category.PII_EXPOSURE,
    Category.PHI_EXPOSURE,
    Category.SOURCE_CODE_LEAK,
    Category.CONFIDENTIAL_DATA,
    Category.UNSANCTIONED_AI,
    # Agentic tool-use — a risky MCP action / poisoned tool is itself the threat.
    Category.MCP_UNTRUSTED_SERVER,
    Category.MCP_INTEGRITY,
    Category.SENSITIVE_RESOURCE_ACCESS,
    Category.DANGEROUS_COMMAND,
    Category.TOOL_POISONING,
    Category.UNSAFE_AUTONOMY,
    # Supply chain — a risky/malicious dependency is itself the threat.
    Category.DEPENDENCY_RISK,
    # CI runners — an exploitable workflow configuration is itself the exposure.
    Category.CI_WORKFLOW_RISK,
    # Endpoint hygiene — a live credential sitting at rest is itself the exposure.
    Category.CREDENTIAL_AT_REST,
    # Access governance — an LLM returning restricted data to the wrong person is the risk.
    Category.DATA_OVERSHARING,
    # Agent authorization — an agent acting outside its least-privilege role is the risk.
    Category.AGENT_AUTHZ,
    # Device health — a capture plane that is down/conflicted/failing-open IS the exposure
    # (traffic passing ungoverned), even though no attacker is present in the content.
    Category.POSTURE_GAP,
}


def _drop_uncorroborated_ml_code(signals: list[Signal]) -> list[Signal]:
    """The ML code classifier scores code-ness, not proprietary-ness — it reads a generic SQL
    join, a React counter, or a docker-compose file as source code exactly like an internal
    module. On its own that is noise: developers paste ordinary code into AI tools constantly,
    and a lone `source_code_ml` was raising a source_code_leak finding on every snippet. Its
    own contract is to CORROBORATE the rules-based source-code check ("cannot max a verdict
    alone"), so keep it only when a non-ML source-code / confidential signal also fired; drop
    it when it stands alone, so a generic paste stays benign while proprietary code (which the
    rules check flags on its structural tells) still escalates — now with the ML agreeing."""
    if not any(s.effective_check == "source_code_ml" for s in signals):
        return signals
    corroborated = any(
        s.effective_check != "source_code_ml"
        and s.category in (Category.SOURCE_CODE_LEAK, Category.CONFIDENTIAL_DATA)
        for s in signals)
    if corroborated:
        return signals
    return [s for s in signals if s.effective_check != "source_code_ml"]


def _saturating_combine(contributions: list[float]) -> float:
    """Probabilistic OR: 1 - Π(1 - c). Saturates toward 1.0."""
    acc = 1.0
    for c in contributions:
        acc *= (1.0 - max(0.0, min(1.0, c)))
    return 1.0 - acc


def severity_for(risk: int) -> tuple[str, str]:
    """Map a 0..100 risk score to (severity, recommended_action). The single source of
    these thresholds — score() and the origin-severity boost both call it so a bumped
    risk lands on exactly the same bands as a natively-scored one."""
    if risk >= 80:
        return "critical", "block"
    if risk >= 60:
        return "high", "quarantine"
    if risk >= 35:
        return "suspicious", "quarantine"
    if risk >= 15:
        return "low", "monitor"
    return "benign", "allow"


def score(signals: list[Signal]) -> Verdict:
    signals = _drop_uncorroborated_ml_code(signals)
    real = [s for s in signals if s.contribution > 0.0]

    ai_conf = _saturating_combine(
        [s.contribution for s in real if s.category in _AI_CATEGORIES]
    )
    attack_conf = _saturating_combine(
        [s.contribution for s in real if s.category in _ATTACK_CATEGORIES]
    )

    # Base risk is driven by attack intent; AI-generation is an amplifier, not a
    # threat on its own (plenty of benign mail is AI-written).
    base = attack_conf
    # Synergy: AI-crafted *and* attacking → escalate. Up to +35% of headroom.
    synergy = 0.35 * ai_conf * attack_conf
    combined = min(1.0, base + synergy)

    risk = round(combined * 100)

    ai_generated = ai_conf >= 0.5
    attack_intent = attack_conf >= 0.45

    severity, action = severity_for(risk)

    # Strongest evidence first.
    ordered = sorted(real, key=lambda s: s.contribution, reverse=True)

    return Verdict(
        risk_score=risk,
        severity=severity,
        recommended_action=action,
        ai_generated=ai_generated,
        attack_intent=attack_intent,
        signals=ordered,
    )
