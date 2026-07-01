"""Normalize text before keyword matching so obfuscation doesn't trivially bypass rules.

Keyword detectors (injection/jailbreak/exfil/confidentiality) are easy to dodge with
Unicode tricks: fullwidth or homoglyph letters ("ｉｇｎｏｒｅ", Cyrillic "іgnоrе"),
zero-width characters wedged between letters, or exotic spacing. `normalize_for_match`
folds those back to plain ASCII-ish text so the same keyword lists still hit.

The *original* text is still used for evidence and for the zero-width/base64 signals —
this only produces a cleaned view for substring matching.
"""
from __future__ import annotations

import re
import unicodedata

# Zero-width, bidi, and Unicode-tag characters used to hide/smuggle content.
_ZERO_WIDTH = re.compile(
    r"[​-‏‪-‮⁠-⁤﻿]|[\U000e0000-\U000e007f]")

# Common homoglyphs (Cyrillic/Greek lookalikes) → Latin. NFKC already handles fullwidth
# and many compatibility forms; this covers same-script-looking substitutions it won't.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ѕ": "s",
    "і": "i", "ј": "j", "к": "k", "н": "h", "м": "m", "т": "t", "в": "b",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}


def normalize_for_match(text: str) -> str:
    """Return a folded view of `text` for keyword matching (NFKC, no zero-width,
    homoglyphs→Latin, collapsed whitespace)."""
    if not text:
        return text
    t = unicodedata.normalize("NFKC", text)
    t = _ZERO_WIDTH.sub("", t)
    t = t.translate(_HOMOGLYPH_TABLE)
    t = re.sub(r"[ \t ]{2,}", " ", t)
    return t
