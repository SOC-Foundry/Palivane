"""A lightweight offline text classifier — logistic regression over hashed features,
trained with SGD, serialized as JSON sparse weights. Stdlib only.

Why this shape: it preserves Palivane's no-API-key / offline promise (no model server, no
provider call), infers in microseconds (a dot product over the nonzero buckets of one
vector — see the eval harness latency numbers), and the weights are a plain JSON file small
enough to ship in the repo. It is NOT a transformer; it's a strong linear baseline whose job
is to catch *phrasing regexes miss* and to be honest about whether that's worth shipping.

The model is a scorer, never an authority on its own: the intended wiring is an additional
signal into the existing engine (raise confidence / add a category), gated behind a flag and
only when it measurably beats the regex baseline on held-out data. Training + evaluation live
in scripts/train_classifier.py; this module is just fit/predict/save/load.
"""
from __future__ import annotations

import json
import math

from .features import vectorize


class LogisticClassifier:
    """Binary logistic regression with L2 regularization, sparse weights."""

    def __init__(self, weights: dict[int, float] | None = None, bias: float = 0.0,
                 threshold: float = 0.5, meta: dict | None = None):
        self.w: dict[int, float] = weights or {}
        self.bias = bias
        self.threshold = threshold
        self.meta = meta or {}

    def _score(self, vec: dict[int, float]) -> float:
        z = self.bias + sum(self.w.get(b, 0.0) * v for b, v in vec.items())
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def proba(self, text: str) -> float:
        return self._score(vectorize(text))

    def predict(self, text: str) -> bool:
        return self.proba(text) >= self.threshold

    # --- training -----------------------------------------------------------------------

    @classmethod
    def train(cls, examples: list[tuple[str, int]], *, epochs: int = 25, lr: float = 0.5,
              l2: float = 1e-4, seed: int = 1) -> "LogisticClassifier":
        """SGD over (text, label∈{0,1}). Deterministic shuffle from `seed` (no Math.random —
        a fixed LCG), so training is reproducible."""
        data = [(vectorize(t), y) for t, y in examples]
        w: dict[int, float] = {}
        bias = 0.0
        rng = seed or 1
        order = list(range(len(data)))
        for _ in range(epochs):
            for i in range(len(order) - 1, 0, -1):          # Fisher–Yates with the LCG
                rng = (rng * 1103515245 + 12345) & 0x7FFFFFFF
                j = rng % (i + 1)
                order[i], order[j] = order[j], order[i]
            for idx in order:
                vec, y = data[idx]
                z = bias + sum(w.get(b, 0.0) * v for b, v in vec.items())
                pred = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
                err = pred - y
                bias -= lr * err
                for b, v in vec.items():
                    w[b] = w.get(b, 0.0) * (1.0 - lr * l2) - lr * err * v
        w = {b: round(val, 6) for b, val in w.items() if abs(val) > 1e-4}
        return cls(weights=w, bias=round(bias, 6))

    # --- persistence --------------------------------------------------------------------

    def to_json(self) -> str:
        return json.dumps({"bias": self.bias, "threshold": self.threshold,
                           "meta": self.meta,
                           "weights": {str(b): v for b, v in self.w.items()}})

    @classmethod
    def from_json(cls, blob: str) -> "LogisticClassifier":
        d = json.loads(blob)
        return cls(weights={int(k): v for k, v in d.get("weights", {}).items()},
                   bias=d.get("bias", 0.0), threshold=d.get("threshold", 0.5),
                   meta=d.get("meta", {}))
