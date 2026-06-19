"""Scoring-fusion behavior: saturation, the AI×attack synergy, and severity bands."""

from __future__ import annotations

from app.detectors.base import Category, Signal
from app.scoring import score


def _sig(category: Category, weight: float, confidence: float) -> Signal:
    return Signal(category, "t", "d", weight, confidence, "test")


def test_no_signals_is_benign():
    v = score([])
    assert v.risk_score == 0
    assert v.severity == "benign"
    assert v.recommended_action == "allow"
    assert not v.ai_generated and not v.attack_intent


def test_ai_alone_is_not_an_attack():
    # AI-generation on its own carries no base risk — plenty of benign mail is AI-written.
    v = score([_sig(Category.AI_GENERATED, 0.9, 0.95)])
    assert v.attack_intent is False
    assert v.risk_score < 15
    assert v.severity == "benign"


def test_attack_drives_base_risk():
    v = score([_sig(Category.PROMPT_INJECTION, 0.9, 0.9)])
    assert v.attack_intent is True
    assert v.risk_score >= 60


def test_ai_plus_attack_escalates_above_attack_alone():
    attack_only = score([_sig(Category.PROMPT_INJECTION, 0.8, 0.7)])
    combined = score([
        _sig(Category.PROMPT_INJECTION, 0.8, 0.7),
        _sig(Category.AI_GENERATED, 0.8, 0.9),
    ])
    # Synergy term must push the combined verdict strictly higher.
    assert combined.risk_score > attack_only.risk_score
    assert combined.ai_generated and combined.attack_intent


def test_saturation_caps_at_100():
    many = [_sig(Category.PROMPT_INJECTION, 1.0, 1.0) for _ in range(20)]
    v = score(many)
    assert v.risk_score == 100
    assert v.severity == "critical"
    assert v.recommended_action == "block"


def test_zero_contribution_signals_ignored():
    # The judge emits weight=0 placeholders when unavailable; they must not count.
    v = score([_sig(Category.PROMPT_INJECTION, 0.0, 0.0), _sig(Category.AI_GENERATED, 0.0, 1.0)])
    assert v.risk_score == 0
    assert v.signals == []


def test_signals_ordered_by_contribution():
    v = score([
        _sig(Category.JAILBREAK, 0.3, 0.4),
        _sig(Category.PROMPT_INJECTION, 0.9, 0.9),
        _sig(Category.DATA_EXFILTRATION, 0.5, 0.5),
    ])
    contribs = [s.contribution for s in v.signals]
    assert contribs == sorted(contribs, reverse=True)


def test_severity_bands_are_monotonic():
    # As a single attack signal strengthens, severity never decreases.
    seen = []
    for conf in (0.2, 0.4, 0.6, 0.8, 1.0):
        seen.append(score([_sig(Category.PROMPT_INJECTION, 1.0, conf)]).risk_score)
    assert seen == sorted(seen)
