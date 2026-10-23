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
governs this signal identically.

"Cannot max a verdict alone" is enforced in scoring.py, not left to the weights: a lone
code hint is dropped (_drop_uncorroborated_ml_code) and a lone injection hint is held at
`low` (_cap_uncorroborated_hints). Both hints are recorded either way; what they cannot do
without a rule-based check agreeing is raise an alert."""

from __future__ import annotations

import logging
from pathlib import Path

from ..ml.classifier import LogisticClassifier
from ..ml.features import vectorize
from ..scoring import unscanned_marker
from .base import AnalysisInput, Category, Signal, Surface

_log = logging.getLogger("palivane.ml")

_MIN_LEN = 120          # under this, n-gram statistics are noise
_THRESHOLD = 0.85       # p(code) to speak at all; confidence tracks p above it
_WINDOW = 240           # must match the training chunk size (scripts/train_code_classifier)
_STEP = 120             # half a window: any span of up to 120 characters lies whole in one
_SCAN_CAP = 100_000     # every character up to here is scored (excerpts.MAX_SCAN); past
                        # it only the tail is, and the verdict says so (_truncated)

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_INJ_THRESHOLD = 0.70   # held-out precision is 1.0 at 0.5; this adds margin, recall is
                        # the sacrifice a corroborating signal can afford


def _load(name: str) -> LogisticClassifier | None:
    path = _DATA_DIR / name
    try:
        return LogisticClassifier.from_json(path.read_text())
    except (OSError, ValueError, KeyError):
        _log.warning("classifier weights missing/unreadable (%s) — that ML task off", path)
        return None


class MLClassifierDetector:
    name = "ml_classifier"
    surfaces = {Surface.AI_USAGE, Surface.LLM_IO, Surface.COLLAB}

    def __init__(self) -> None:
        self._model = _load("code_classifier.json")
        self._inj = _load("injection_classifier.json")

    def p_code(self, text: str) -> float:
        """P(the text contains source code). Scored in training-shaped windows (the model
        was fit on ~240-char chunks; a whole document dilutes the L2-normalized features
        toward indifference) and aggregated by max — a code block pasted INSIDE prose is
        exactly the leak this tier exists to catch. 0.0 when the model is unavailable or
        the input is too short to carry n-gram signal."""
        return self._scores(text, injection=False)[1]

    def p_injection(self, text: str) -> float:
        """P(the text carries a prompt injection). Same window-max treatment — an
        injection appended to a long benign paste is the classic smuggle."""
        return self._scores(text, code=False)[0]

    def _scores(self, text: str, *, injection: bool = True,
                code: bool = True) -> tuple[float, float]:
        """(p_injection, p_code) over the same windows, each window vectorized once.

        The windows overlap by half (_windows): nothing up to _SCAN_CAP falls between them,
        and any span of up to _STEP characters lies whole inside at least one, so a short
        payload is not lost by being cut in two. Max-aggregated: one window that reads as
        code or injection is the finding."""
        inj = self._inj if injection and len(text) >= 25 else None
        model = self._model if code and len(text) >= _MIN_LEN else None
        if inj is None and model is None:
            return 0.0, 0.0
        pi = pc = 0.0
        if inj is not None and len(text) <= 400:
            pi, inj = inj.proba(text), None      # short: scored whole, as trained
        if inj is None and model is None:
            return pi, pc
        for w in _windows(text):
            vec = vectorize(w)
            if inj is not None:
                pi = max(pi, inj.proba_vec(vec))
            if model is not None and len(w) >= _MIN_LEN:
                pc = max(pc, model.proba_vec(vec))
        return pi, pc

    def _truncated(self, text: str) -> Signal:
        """The partial-scan marker (scoring.unscanned_marker, the same one engine.py leaves
        for a detector that raised): weight 0, so it never moves the score, but the verdict
        carries `unscanned: ["ml_classifier"]` so "the classifier read part of this" cannot
        read as "the classifier read all of it and found nothing"."""
        return unscanned_marker(
            f"detector={self.name}", "Classifier read only part of the text",
            f"The on-box classifiers scored the first {_SCAN_CAP:,} and the last {_WINDOW} "
            f"characters of {len(text):,}; the rest was not scored. The verdict reflects "
            "the part that was read.", detector=self.name)

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        out: list[Signal] = []
        text = item.content
        # Injection is read on the AI surfaces only; collab gets the code task alone.
        pi, p = self._scores(text, injection=item.surface in (Surface.LLM_IO, Surface.AI_USAGE))
        if len(text) > _SCAN_CAP and (self._model is not None or self._inj is not None):
            out.append(self._truncated(text))
        if pi >= _INJ_THRESHOLD:
            iev = (self._inj.meta.get("eval") or {}) if self._inj else {}
            out.append(Signal(
                category=Category.PROMPT_INJECTION,
                title="Prompt injection (ML classifier)",
                detail=f"The on-box classifier reads this as injection phrasing "
                       f"(p={pi:.2f}; held-out precision "
                       f"{iev.get('precision', '?')}, zero false positives on a "
                       "benign-prose check). Catches the paraphrases the pattern "
                       "rules miss. A hint: on its own it is recorded as low "
                       "severity, and it escalates only when a rule-based check "
                       "also flags the text.",
                weight=0.4, confidence=round(min(pi, 0.95), 2),
                detector=self.name, evidence=f"p(injection)={pi:.2f}",
                check="prompt_injection_ml"))
        if p < _THRESHOLD:
            return out
        ev = (self._model.meta.get("eval") or {}) if self._model else {}
        return out + [Signal(
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


def _windows(text: str) -> list[str]:
    """_WINDOW-character windows stepped by _STEP over text[:_SCAN_CAP], the last one flush
    with that span's end, so every character up to the cap is scored. Past the cap the tail
    window is added: appended-after-a-long-paste is the classic smuggle. Cost is linear in
    the text, bounded by the cap: ~830 windows at most."""
    end = min(len(text), _SCAN_CAP)
    if end <= _WINDOW:
        return [text[:end]]
    starts = [*range(0, end - _WINDOW, _STEP), end - _WINDOW]
    windows = [text[i:i + _WINDOW] for i in starts]
    if len(text) > _SCAN_CAP:
        windows.append(text[-_WINDOW:])
    return windows
