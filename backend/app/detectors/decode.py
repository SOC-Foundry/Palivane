"""Shared best-effort decoders for obfuscated payloads (base64 / hex / percent-encoding).

Two detectors decode-then-rescan: prompt_threats checks a decoded blob against its attack
phrase lists, and shadow_ai re-scans it for PII / secrets. Both share the same primitives
here so the ">85% printable" guard and the decode-work bounds live in one place.

stdlib only. All decode work is bounded — each blob is truncated before decoding and the
number of blobs per input is capped — so a base64/hex flood on the ai_usage surface can't
turn into unbounded work (the ReDoS discipline the rest of the package keeps).
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

# Cap each blob before decoding, and cap how many blobs we decode per input.
_MAX_BLOB = 4096
_MAX_BLOBS = 32

# Lower thresholds than prompt_threats' bare-blob smuggling flag (BASE64_RE, {60,}). These
# decode-and-rescan views only ever emit a signal when the DECODED text carries a real
# attack phrase / PII / secret, so a short blob can't false-positive here — a benign
# 16-char token won't decode to an SSN. Charset-only classes, no multiline anchors: linear.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


def printable_text(raw: bytes) -> str:
    """Decode bytes to text only if it looks like real text (not binary): >85% printable."""
    text = raw.decode("utf-8", "replace")
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.85 else ""


def decode_b64(blob: str) -> str:
    """Best-effort decode of a base64 blob to text; '' if it isn't decodable text."""
    blob = blob[:_MAX_BLOB]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(blob + "=" * (-len(blob) % 4))
        except (binascii.Error, ValueError):
            continue
        if (t := printable_text(raw)):
            return t
    return ""


def decode_hex(blob: str) -> str:
    """Best-effort decode of a hex run to text; '' if it isn't decodable text."""
    blob = blob[:_MAX_BLOB]
    if len(blob) % 2:
        blob = blob[:-1]
    try:
        return printable_text(bytes.fromhex(blob))
    except ValueError:
        return ""


def decode_obfuscated(text: str) -> str:
    """Decode every base64/hex blob (bounded) plus a percent-decoded view, and return the
    concatenated printable decodings ('' if nothing decoded). Meant only to be re-scanned
    for attack phrases / PII / secrets an encoded blob is hiding — never surfaced verbatim."""
    out: list[str] = []
    for n, m in enumerate(_B64_RE.finditer(text)):
        if n >= _MAX_BLOBS:
            break
        if (d := decode_b64(m.group(0))):
            out.append(d)
    for n, m in enumerate(_HEX_RE.finditer(text)):
        if n >= _MAX_BLOBS:
            break
        if (d := decode_hex(m.group(0))):
            out.append(d)
    if "%" in text:
        try:
            dec = urllib.parse.unquote(text)
            if dec != text:
                out.append(dec)
        except (ValueError, UnicodeDecodeError):
            pass
    return "\n".join(out)
