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


# Leetspeak → letters, for a SECONDARY keyword-match view only (never for secret/PII regexes,
# which need real digits). Safe because attack keyword lists are multi-word phrases — benign
# text almost never folds into "ignore all previous instructions".
_LEET_TABLE = {ord(k): v for k, v in
               {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}.items()}


def leet_fold(text: str) -> str:
    """A leetspeak-folded view of the normalized text ('1gn0r3' → 'ignore')."""
    return normalize_for_match(text).translate(_LEET_TABLE)


# Command-keyword leet fold. Identical to _LEET_TABLE except `1`→`l` (not `i`): shell
# keywords use the letter L (`curl`, `ssl`, `url`), so `cur1`→`curl`, `-551`→`-ssl`,
# `5h`→`sh`, `h77p`→`http`. Only used by the dangerous-COMMAND matchers, where the URL/
# argument middle is a wildcard, so an occasional wrong 1→l elsewhere in the string doesn't
# change what the command regex keys on. Never applied to prose keyword lists (that path
# keeps _LEET_TABLE with 1→i).
_CMD_LEET_TABLE = {ord(k): v for k, v in
                   {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
                    "@": "a", "$": "s"}.items()}


def command_leet_fold(text: str) -> str:
    """A leetspeak-folded view tuned for shell-command keywords ('cur1 … | 5h' → 'curl … | sh')."""
    return normalize_for_match(text).translate(_CMD_LEET_TABLE)


def normalize_keep_lines(text: str) -> str:
    """normalize_for_match without the whitespace collapse: same NFKC / zero-width /
    homoglyph folding, but line structure survives. For patterns that must anchor to the
    start of a line — a forged `system:` turn marker is an injection, the tail of
    "a three-level loading system:" is not, and only the line break tells them apart."""
    if not text:
        return text
    t = unicodedata.normalize("NFKC", text)
    t = _ZERO_WIDTH.sub("", t)
    return t.translate(_HOMOGLYPH_TABLE)


def normalize_for_match(text: str) -> str:
    """Return a folded view of `text` for keyword matching (NFKC, no zero-width,
    homoglyphs→Latin, collapsed whitespace)."""
    if not text:
        return text
    t = normalize_keep_lines(text)
    # Collapse ANY whitespace run (incl. newlines/tabs/nbsp) to a single space, so a keyword
    # split across lines ("ignore\nall\nprevious") still matches the phrase lists.
    t = re.sub(r"\s+", " ", t)
    return t
