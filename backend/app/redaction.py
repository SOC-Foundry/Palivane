"""Redact secrets & PII from finding content before it's stored.

Warden blocks a prompt *because* it contains an AWS key or an SSN — so persisting that
prompt verbatim would turn the findings DB into a plaintext-secret honeypot. Detection
runs on the raw content; only the *stored* copy is masked. Toggle with
`WARDEN_REDACT_FINDINGS` (default on).
"""
from __future__ import annotations

import re

from .detectors.patterns import SECRET_PATTERNS
from .detectors.shadow_ai import CC_CANDIDATE_RE, SSN_RE, _luhn_ok

MAX_STORED = 20_000   # also cap stored content so a huge paste can't bloat the row


def _mask_card(m: re.Match) -> str:
    return "«redacted:card»" if _luhn_ok(re.sub(r"[ -]", "", m.group(0))) else m.group(0)


def redact_text(text: str) -> str:
    """Replace known secrets, SSNs, and Luhn-valid card numbers with «redacted:…» markers."""
    if not text:
        return text
    for label, rx in SECRET_PATTERNS:
        text = rx.sub(f"«redacted:{label}»", text)
    text = SSN_RE.sub("«redacted:SSN»", text)
    text = CC_CANDIDATE_RE.sub(_mask_card, text)
    return text[:MAX_STORED]
