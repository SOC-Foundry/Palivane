"""Scoring-fusion behavior: saturation, the AI×attack synergy, and severity bands."""

from __future__ import annotations

import pytest

from app.detectors.base import Category, Signal
from app.scoring import _HINT_CAP, score, severity_for


def _sig(category: Category, weight: float, confidence: float) -> Signal:
    return Signal(category, "t", "d", weight, confidence, "test")


def _hint(p: float) -> Signal:
    """What MLClassifierDetector emits when it reads text as injection with probability p."""
    return Signal(Category.PROMPT_INJECTION, "Prompt injection (ML classifier)", "d", 0.4, p,
                  "ml_classifier", evidence=f"p(injection)={p:.2f}", check="prompt_injection_ml")


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


def test_data_leak_scores_risk_but_is_not_attack_intent():
    # A leaked secret is a real risk that must drive the score, but it is a data/hygiene
    # problem, not an adversary — so attack_intent stays False (the FP we fixed).
    v = score([_sig(Category.SECRET_LEAK, 0.9, 0.9)])
    assert v.risk_score >= 60          # still scores as a serious risk
    assert v.attack_intent is False    # ...but is not labeled an attack


def test_injection_is_attack_intent():
    v = score([_sig(Category.PROMPT_INJECTION, 0.9, 0.9)])
    assert v.attack_intent is True     # a genuine adversarial category still flags


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


# --- An ML hint on its own is a record, not an alert -------------------------------------
#
# The injection classifier is trained on synthetic data and its own contract is that it
# corroborates ("cannot max a verdict alone"). The arithmetic did not enforce that: weight
# 0.4 x confidence p is 28 to 38 points, and 35 is the `suspicious` line. In practice every
# one of the six hint-only findings one operator triaged (p between 0.70 and 0.89) was
# dismissed, and five of them only crossed the line because the unrecognized-destination
# baseline that rides on every prompt to an unsanctioned host added a few points. A hint
# stands on its own at most as a `low` record; a second, independent check that saw an
# attack is what lets it escalate.


@pytest.mark.parametrize("p", [0.70, 0.78, 0.875, 0.89, 0.95])
def test_a_lone_injection_hint_never_leaves_the_low_band(p):
    v = score([_hint(p)])
    assert v.severity == "low" and v.recommended_action == "monitor"
    assert v.risk_score <= _HINT_CAP
    # recorded, not discarded: the finding still shows what the classifier read
    assert [s.effective_check for s in v.signals] == ["prompt_injection_ml"]


@pytest.mark.parametrize("p, destination", [
    (0.71, _sig(Category.UNSANCTIONED_AI, 0.28, 0.45)),     # "Unrecognized AI destination"
    (0.89, _sig(Category.UNSANCTIONED_AI, 0.28, 0.45)),
    (0.70, _sig(Category.UNSANCTIONED_AI, 0.35, 0.65)),     # "Unsanctioned AI tool: <known>"
    (0.95, _sig(Category.UNSANCTIONED_AI, 0.35, 0.65)),
])
def test_where_the_text_is_going_does_not_corroborate_a_hint(p, destination):
    # A destination says nothing about whether the text is an injection.
    v = score([_hint(p), destination])
    assert v.severity == "low" and v.risk_score <= _HINT_CAP, v.risk_score


def test_a_check_that_saw_the_attack_lets_the_hint_escalate():
    rule = Signal(Category.PROMPT_INJECTION, "Instruction override", "d", 0.8, 0.9,
                  "prompt_threats", check="prompt_injection")
    together = score([_hint(0.89), rule])
    # rules and ML agreeing is the escalation the hint exists for: the plain saturating OR,
    # no cap, and strictly more than the rule alone
    assert together.risk_score == round(100 * (1 - (1 - 0.8 * 0.9) * (1 - 0.4 * 0.89)))
    assert together.risk_score > score([rule]).risk_score
    assert together.risk_score > _HINT_CAP


def test_a_hint_beside_an_unrelated_risk_does_not_hold_it_down():
    # The cap is for a hint standing alone. A leaked secret drives its own verdict, and it
    # must not be held at `low` because a hint happens to sit next to it.
    secret = _sig(Category.SECRET_LEAK, 0.9, 0.85)
    v = score([_hint(0.89), secret])
    assert v.risk_score == round(100 * (1 - (1 - 0.9 * 0.85) * (1 - 0.4 * 0.89)))
    assert v.risk_score > score([secret]).risk_score


def test_a_code_hint_that_the_rules_agree_with_is_not_capped():
    rules = Signal(Category.SOURCE_CODE_LEAK, "Source code in outbound content", "d", 0.8, 0.8,
                   "shadow_ai")
    ml = Signal(Category.SOURCE_CODE_LEAK, "Source code (ML classifier)", "d", 0.35, 0.97,
                "ml_classifier", check="source_code_ml")
    v = score([rules, ml])
    assert v.risk_score == round(100 * (1 - (1 - 0.8 * 0.8) * (1 - 0.35 * 0.97)))
    assert v.risk_score > _HINT_CAP


def test_the_cap_sits_one_under_the_suspicious_line():
    # severity_for owns the bands; the cap is only meaningful as "the top of `low`".
    assert severity_for(_HINT_CAP)[0] == "low"
    assert severity_for(_HINT_CAP + 1)[0] == "suspicious"


def test_engine_records_a_lone_high_probability_injection_hint_as_low(client, monkeypatch):
    # End to end, through the registered detectors, on the surface where it happened. The
    # probability is pinned: the point is what the scorer does with a confident hint, not
    # what this particular classifier makes of a sentence.
    from app.detectors.ml_classifier import MLClassifierDetector
    monkeypatch.setattr(MLClassifierDetector, "p_injection", lambda self, text: 0.93)
    r = client.post("/api/analyze", json={"content": "Please summarize the notes from today's design review meeting.",
                                          "surface": "ai_usage"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "prompt_injection_ml" in {s.get("check") for s in body["signals"]}
    assert body["severity"] == "low" and body["recommended_action"] == "monitor", body
