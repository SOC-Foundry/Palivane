"""The ML detection tier: an on-box code/prose classifier (surface: AI usage / LLM IO /
collab).

This is the wiring app/ml was built for — its header says the model is "a scorer, never
an authority on its own: … an additional signal into the existing engine". Deliberately
boring machine learning: the repo's stdlib logistic regression over hashed word + bigram
+ char-shingle features, trained offline (scripts/train_code_classifier.py) on
honestly-labeled data (this repository's source files vs its documentation prose), CPU-
only and deterministic, with the held-out eval shipped inside the weights file
(backend/data/code_classifier.json: 98% accuracy, 99% precision at training).

What it's for: the BOUNDARY cases the rules-based source-code check reads past — config-
shaped fragments, minified snippets, code without telltale keywords. It emits its own
low-weight signal rather than mutating other detectors' output: under the saturating-OR
scorer it corroborates (rules + ML agree → escalation) but cannot max a verdict alone,
and the sanctioned-coding-tool suppression that governs the source_code_leak category
governs this signal identically."""

from __future__ import annotations

import logging
from pathlib import Path

from ..ml.classifier import LogisticClassifier
from .base import AnalysisInput, Category, Signal, Surface

_log = logging.getLogger("palivane.ml")

_MIN_LEN = 120          # under this, n-gram statistics are noise
_THRESHOLD = 0.85       # p(code) to speak at all; confidence tracks p above it
_WINDOW = 240           # must match the training chunk size (scripts/train_code_classifier)
_STRIDE = 400           # sparse stride: enough windows to find an embedded block, bounded
_SCAN_CAP = 2800        # score at most ~7 windows — keeps worst-case inference ~2ms

_WEIGHTS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "code_classifier.json"


def _load() -> LogisticClassifier | None:
    try:
        return LogisticClassifier.from_json(_WEIGHTS_PATH.read_text())
    except (OSError, ValueError, KeyError):
        _log.warning("code-classifier weights missing/unreadable (%s) — ML tier off",
                     _WEIGHTS_PATH)
        return None


class MLClassifierDetector:
    name = "ml_classifier"
    surfaces = {Surface.AI_USAGE, Surface.LLM_IO, Surface.COLLAB}

    def __init__(self) -> None:
        self._model = _load()

    def p_code(self, text: str) -> float:
        """P(the text contains source code). Scored in training-shaped windows (the model
        was fit on ~240-char chunks; a whole document dilutes the L2-normalized features
        toward indifference) and aggregated by max — a code block pasted INSIDE prose is
        exactly the leak this tier exists to catch. 0.0 when the model is unavailable or
        the input is too short to carry n-gram signal."""
        if self._model is None or len(text) < _MIN_LEN:
            return 0.0
        windows = [text[i:i + _WINDOW] for i in range(0, min(len(text), _SCAN_CAP), _STRIDE)]
        return max((self._model.proba(w) for w in windows if len(w) >= _MIN_LEN),
                   default=0.0)

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        p = self.p_code(item.content)
        if p < _THRESHOLD:
            return []
        ev = (self._model.meta.get("eval") or {}) if self._model else {}
        return [Signal(
            category=Category.SOURCE_CODE_LEAK,
            title="Source code (ML classifier)",
            detail=f"The on-box n-gram classifier reads this as source code (p={p:.2f}; "
                   f"held-out eval {ev.get('accuracy', '?')} accuracy / "
                   f"{ev.get('precision', '?')} precision). Catches the fragments the "
                   "keyword-based check reads past — config blocks, minified snippets.",
            # Low weight by design: alone it warns at most; agreeing with the rules
            # check it escalates. Confidence tracks the model's own probability.
            weight=0.35, confidence=round(min(p, 0.97), 2),
            detector=self.name, evidence=f"p(code)={p:.2f}",
            check="source_code_ml")]
