"""Offline text classification — a stdlib logistic-regression scorer that complements the
regex detectors. See classifier.py for the model and docs/ml-classifier-baseline.md for the
honest benchmark + go/no-go. Not wired into the live detection path until it beats baseline.
"""
from .classifier import LogisticClassifier

__all__ = ["LogisticClassifier"]
