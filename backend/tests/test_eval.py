"""Eval harness: metric math, corpus integrity, and a regression gate on the bundled corpus."""

from __future__ import annotations

from app.eval.corpus import load_corpus
from app.eval.metrics import Metrics, confusion, is_flagged
from app.eval.run import build_report, score_corpus


def test_confusion_and_metrics():
    # 3 TP, 1 FN, 1 FP, 2 TN
    pairs = [(True, True), (True, True), (True, True), (True, False),
             (False, True), (False, False), (False, False)]
    m = confusion(pairs)
    assert (m.tp, m.fn, m.fp, m.tn) == (3, 1, 1, 2)
    assert m.positives == 4
    assert round(m.precision, 3) == 0.75   # 3 / (3+1)
    assert round(m.recall, 3) == 0.75      # 3 / (3+1)
    assert round(m.f1, 3) == 0.75
    assert round(m.accuracy, 3) == round(5 / 7, 3)


def test_metrics_handle_empty_denominators():
    m = Metrics(tp=0, fp=0, tn=5, fn=0)
    assert m.precision == 0.0 and m.recall == 0.0 and m.f1 == 0.0
    assert m.accuracy == 1.0


def test_is_flagged_thresholds():
    assert is_flagged(35, "suspicious")
    assert not is_flagged(34, "suspicious")
    assert is_flagged(80, "critical")
    assert not is_flagged(60, "critical")


def test_corpus_loads_and_is_well_formed():
    corpus = load_corpus()
    assert len(corpus) >= 20
    ids = [e.id for e in corpus]
    assert len(ids) == len(set(ids))  # unique
    assert {"llm_io", "ai_usage", "agent_rules"} <= {e.surface for e in corpus}
    assert all(e.label in ("malicious", "benign") for e in corpus)


def test_bundled_corpus_meets_quality_bar():
    # Regression gate: heuristics-only detection must stay strong on the seed corpus.
    rep = build_report(score_corpus(load_corpus()), "suspicious")
    assert rep["overall"]["recall"] >= 0.9
    assert rep["overall"]["precision"] >= 0.9
    assert rep["overall"]["f1"] >= 0.9
    # Every malicious example should fire at least one expected category.
    assert rep["category_coverage"]["rate"] == 1.0


def test_agent_rules_corpus_gate():
    # Rules-file backdoor detection must separate real injections from benign rules files
    # (the corpus includes FP-traps that mention secrets/tools/"do not").
    rep = build_report(score_corpus(load_corpus()), "suspicious")
    ar = rep["per_surface"].get("agent_rules")
    assert ar is not None and ar["support"] >= 12
    assert ar["precision"] >= 0.9 and ar["recall"] >= 0.9


def test_session_correlation_sequence_gate():
    # The stateful chain detector must be clean on the labeled sequence set (no false
    # chains, no missed chains). sequences.main() returns 0 only when fp==0 and fn==0.
    from app.eval.sequences import main as seq_main
    assert seq_main(["--json"]) == 0


def test_report_lists_misclassifications_at_strict_cutoff():
    # At 'critical', recall must drop (some real threats score below 80) — the sweep
    # is meaningful, and misclassifications are reported.
    rep = build_report(score_corpus(load_corpus()), "critical")
    assert rep["overall"]["recall"] < 1.0
    assert len(rep["misclassified"]) > 0
