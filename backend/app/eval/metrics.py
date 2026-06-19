"""Pure classification metrics for the detection eval harness.

Detection is treated as binary: a finding is *flagged* if its risk score clears an
operating threshold (a severity cutoff). We compare that against the corpus label
(malicious vs benign) to get a confusion matrix and precision/recall/F1.
"""

from __future__ import annotations

from dataclasses import dataclass

# Lower bound of each severity band (mirrors scoring.score()).
SEVERITY_CUTOFFS = {"low": 15, "suspicious": 35, "high": 60, "critical": 80}
CUTOFF_ORDER = ["low", "suspicious", "high", "critical"]


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def positives(self) -> int:
        """Actual malicious examples (the support that matters for recall)."""
        return self.tp + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "support": self.total, "positives": self.positives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


def confusion(pairs: list[tuple[bool, bool]]) -> Metrics:
    """`pairs` is a list of (actual_malicious, predicted_flagged)."""
    tp = fp = tn = fn = 0
    for actual, predicted in pairs:
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1
    return Metrics(tp=tp, fp=fp, tn=tn, fn=fn)


def is_flagged(risk_score: int, cutoff: str) -> bool:
    return risk_score >= SEVERITY_CUTOFFS[cutoff]
