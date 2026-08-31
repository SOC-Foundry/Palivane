"""Transformer-encoder classification, run LOCALLY on CPU. Enterprise.

Path 1 (ml/confidential.py) is a linear model over hashed n-grams: microseconds, stdlib,
no dependency, and it beats the marker-based regex on unlabelled confidential prose by a
wide margin. It is also the ceiling of what a bag-of-ngrams can do — it cannot use word
order or context, so "we are acquiring them" and "they are acquiring us" are the same vector.

This is the tier above: a fine-tuned encoder (ModernBERT-class, 149M-395M parameters) run
through ONNX Runtime on CPU. Harmonic publishes 46ms median / 81ms p95 for the equivalent
binary classifier — on GPU instances in their own cloud, which means the customer's content
leaves the customer's environment to be classified. That is the whole reason this file
exists as a local runtime rather than a client for somebody's inference API.

Three properties it must keep:

  * **Soft dependency.** onnxruntime and a tokenizer are optional. Missing, this is inert
    and the linear model still runs — exactly how ocr.py behaves.
  * **Local, always.** No HTTP client, no SDK, no endpoint URL. There is a test asserting
    this module contains no network client at all, because the moment it has one, the
    product's central claim is false.
  * **Plan-gated.** The encoder is the paid tier; the linear model is not.

WHAT IS NOT HERE: trained weights. Fine-tuning ModernBERT needs a GPU run over a labelled
corpus, and no such corpus exists yet (see docs/ml-classifier-baseline.md — the gate wants a
real, time-windowed holdout). This is the runtime a model gets dropped into, with the
loading, threading, truncation and failure behaviour settled, so producing weights is the
only remaining step rather than the first of several.
"""

from __future__ import annotations

import os
import threading

_MAX_TOKENS = 512            # encoder context; longer input is chunked, not silently cut
_MAX_CHUNKS = 4              # bound the cost of one very long document
_lock = threading.Lock()
_session = None              # None = unprobed, False = unavailable
_tokenizer = None


def _paths() -> tuple[str, str]:
    from ..config import settings
    return ((getattr(settings, "ml_encoder_model", "") or "").strip(),
            (getattr(settings, "ml_encoder_tokenizer", "") or "").strip())


def runtime_available() -> bool:
    """True when onnxruntime and a tokenizer library are importable. Probed, not assumed:
    the deploy image does not carry them, so the default answer is False."""
    try:
        import onnxruntime  # noqa: F401
        import tokenizers   # noqa: F401
    except Exception:                                         # noqa: BLE001
        return False
    return True


def _load():
    """(session, tokenizer) or (None, None). Cached, including the failure."""
    global _session, _tokenizer
    if _session is not None:
        return (_session or None), _tokenizer
    with _lock:
        if _session is not None:
            return (_session or None), _tokenizer
        model_path, tok_path = _paths()
        if not model_path or not os.path.isfile(model_path) or not runtime_available():
            _session = False
            return None, None
        try:
            import onnxruntime
            from tokenizers import Tokenizer
            opts = onnxruntime.SessionOptions()
            # One thread per session: this runs inside a request worker, and letting ORT
            # fan out across every core turns one large document into a latency spike for
            # every other request on the box.
            opts.intra_op_num_threads = 1
            opts.inter_op_num_threads = 1
            _session = onnxruntime.InferenceSession(
                model_path, sess_options=opts, providers=["CPUExecutionProvider"])
            _tokenizer = Tokenizer.from_file(tok_path) if tok_path else None
        except Exception:                                     # noqa: BLE001
            _session = False
            return None, None
        return _session, _tokenizer


def available(tenant=None) -> bool:
    """Whether the encoder may run for this tenant: weights loadable AND the plan allows it."""
    if _load()[0] is None:
        return False
    if tenant is None:
        return True
    from ..plans import has_feature
    return has_feature(tenant, "ml_encoder")


def _chunks(tokenizer, text: str) -> list[list[int]]:
    """Token-id windows of at most _MAX_TOKENS. A long document is scored in pieces and the
    strongest piece wins, rather than being truncated to its first page — the sensitive
    paragraph is rarely at the top."""
    ids = tokenizer.encode(text).ids
    if not ids:
        return []
    body = _MAX_TOKENS - 2
    return [ids[i:i + body] for i in range(0, min(len(ids), body * _MAX_CHUNKS), body)]


def score(text: str, tenant=None) -> float | None:
    """P(confidential) from the encoder, or None when it cannot or may not run.

    Never raises: a broken model file, a shape mismatch or a missing tokenizer all mean the
    caller falls back to the linear model, the same way a missing OCR install means the
    text scan simply proceeds."""
    if not (text or "").strip() or not available(tenant):
        return None
    session, tokenizer = _load()
    if session is None or tokenizer is None:
        return None
    try:
        best = 0.0
        for ids in _chunks(tokenizer, text):
            feed = {"input_ids": [ids], "attention_mask": [[1] * len(ids)]}
            logits = session.run(None, feed)[0][0]
            best = max(best, _sigmoid(float(logits[-1])) if len(logits) == 1
                       else _softmax_positive(logits))
        return best
    except Exception:                                         # noqa: BLE001
        return None


def _sigmoid(x: float) -> float:
    import math
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, x))))


def _softmax_positive(logits) -> float:
    import math
    vals = [float(v) for v in logits]
    hi = max(vals)
    exps = [math.exp(v - hi) for v in vals]
    return exps[-1] / (sum(exps) or 1.0)


def reset() -> None:
    global _session, _tokenizer
    with _lock:
        _session, _tokenizer = None, None
