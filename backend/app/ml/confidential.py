"""The confidential-content classifier, as a signal into the existing engine.

The shipped `confidential_data` detector fires on explicit markers: the word "confidential",
or an applied sensitivity label (Purview/MIP/TLP). Measured against a corpus of UNLABELLED
confidential material — term sheets, pipeline exports, comp reviews — it finds none of it.
That is the gap, and unlabelled is how this material actually travels.

This loads a small linear model (hashed n-grams + logistic regression, the same machinery
as the injection classifier) and offers a second opinion. Three deliberate limits:

  * **Off unless weights are present.** No model file, no signal, no behaviour change. There
    are no weights in the repo: shipping a model trained on synthetic data would be exactly
    the thing docs/ml-classifier-baseline.md refuses.
  * **Never an authority.** It contributes a signal at a lower weight and confidence than
    the marker path, under its own title, so an analyst can always tell which one spoke and
    a model's opinion cannot on its own reach the block tier.
  * **Local.** A dot product over one sparse vector, ~0.1ms, no provider call. Harmonic's
    equivalent runs on GPU instances in their cloud, which means their customers' content
    leaves to be classified. Ours does not, and that constraint is why this is a linear
    model rather than a transformer.
"""

from __future__ import annotations

import os
import threading

_lock = threading.Lock()
_model = None            # None = not loaded yet, False = unavailable
_MIN_PROBA = 0.80        # a model gets to be confident before it says anything at all


def _path() -> str:
    from ..config import settings
    return (getattr(settings, "ml_confidential_model", "") or "").strip()


def _load():
    global _model
    if _model is not None:
        return _model or None
    with _lock:
        if _model is not None:
            return _model or None
        path = _path()
        if not path or not os.path.isfile(path):
            _model = False
            return None
        try:
            from .classifier import LogisticClassifier
            with open(path, encoding="utf-8") as fh:
                _model = LogisticClassifier.from_json(fh.read())
        except Exception:                                     # noqa: BLE001
            _model = False        # a corrupt weights file must not break detection
            return None
        return _model


def available() -> bool:
    return _load() is not None


def score(text: str) -> float | None:
    """P(confidential) for `text`, or None when no model is loaded."""
    model = _load()
    if model is None or not (text or "").strip():
        return None
    try:
        return float(model.proba(text))
    except Exception:                                         # noqa: BLE001
        return None


def confident(text: str) -> float | None:
    """The probability, but only when it clears the reporting threshold."""
    p = score(text)
    return p if p is not None and p >= _MIN_PROBA else None


def reset() -> None:
    """Drop the cached model — tests, and a weights file replaced under a running process."""
    global _model
    with _lock:
        _model = None
