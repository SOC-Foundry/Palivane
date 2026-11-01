"""Offline text classification — a stdlib logistic-regression scorer that complements the
regex detectors. See classifier.py for the model and docs/ml-classifier-baseline.md for the
honest benchmark + go/no-go. Wired into live detection as corroboration only
(detectors/ml_classifier.py): a lone ML hint is dropped or held at `low` by scoring.py and
cannot raise an alert without a rule-based check agreeing. Letting it act alone waits on the
real-data gate.
"""
from .classifier import LogisticClassifier

__all__ = ["LogisticClassifier"]
