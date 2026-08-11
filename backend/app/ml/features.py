"""Feature hashing for the offline text classifier — stdlib only, no numpy.

The hashing trick maps word and char-ngram tokens into a fixed-width sparse vector via a
stable hash, so there's no vocabulary to store or drift and inference is a dict of nonzero
buckets. Deterministic (hashlib, not Python's salted hash) so a model trained offline scores
identically in the gateway.
"""
from __future__ import annotations

import hashlib
import re

_DIM = 2 ** 18            # 262144 buckets — plenty for this token space, ~0 collision cost
_WORD_RE = re.compile(r"[a-z0-9_]+|[^\sa-z0-9_]", re.I)


def _bucket(token: str) -> int:
    h = hashlib.blake2b(token.encode("utf-8", "ignore"), digest_size=8).digest()
    return int.from_bytes(h, "big") % _DIM


def tokens(text: str) -> list[str]:
    """Word tokens + 3-char shingles of the lowercased text. Char shingles catch the
    obfuscations regexes miss — spaced-out 'i g n o r e', separator-split keys — without a
    language model."""
    low = (text or "").lower()
    words = _WORD_RE.findall(low)
    out = [f"w:{w}" for w in words]
    out += [f"w2:{a}_{b}" for a, b in zip(words, words[1:])]     # word bigrams
    compact = re.sub(r"\s+", " ", low)
    out += [f"c3:{compact[i:i+3]}" for i in range(len(compact) - 2)]
    return out


def vectorize(text: str) -> dict[int, float]:
    """Text -> sparse {bucket: weight}. Log-scaled term counts (diminishing returns on
    repetition), L2-normalized so long and short inputs are comparable."""
    import math

    counts: dict[int, float] = {}
    for t in tokens(text):
        b = _bucket(t)
        counts[b] = counts.get(b, 0.0) + 1.0
    vec = {b: 1.0 + math.log(c) for b, c in counts.items()}
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    return {b: v / norm for b, v in vec.items()}


DIM = _DIM
