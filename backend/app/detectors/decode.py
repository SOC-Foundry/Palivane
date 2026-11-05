"""Shared best-effort decoders for obfuscated payloads (base64 / hex / percent-encoding).

Two detectors decode-then-rescan: prompt_threats checks a decoded blob against its attack
phrase lists, and shadow_ai re-scans it for PII / secrets. Both share the same primitives
here so the ">85% printable" guard and the decode-work bounds live in one place.

stdlib only. All decode work is bounded by a per-input BYTE budget rather than a blob
count, so decoy blobs ahead of the payload can't use up a fixed number of slots, and a
long payload isn't cut at a few KB. Decoded text is decoded again (nested encodings) and
gzip/zlib bodies are inflated, both inside the same budget. When the budget runs out the
caller is told, so it can mark the scan partial instead of reporting clean.
"""
from __future__ import annotations

import base64
import binascii
import functools
import re
import urllib.parse
import zlib
from typing import NamedTuple

# Encoded characters decoded per input, across every blob and level; one blob's share; how
# many levels deep decoded text is decoded again; how far a compressed body may inflate.
_BUDGET = 512 * 1024
_MAX_BLOB = 128 * 1024
_MAX_DEPTH = 3
_MAX_INFLATE = 256 * 1024

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


def _inflate(raw: bytes) -> bytes:
    """A gzip or zlib body, inflated (bounded); the bytes unchanged when it is neither."""
    if raw[:2] == b"\x1f\x8b":
        wbits = 16 + zlib.MAX_WBITS
    elif len(raw) >= 2 and raw[0] == 0x78 and (raw[0] << 8 | raw[1]) % 31 == 0:
        wbits = zlib.MAX_WBITS
    else:
        return raw
    try:
        return zlib.decompressobj(wbits).decompress(raw, _MAX_INFLATE)
    except zlib.error:
        return raw


def decode_b64(blob: str) -> str:
    """Best-effort decode of a base64 blob to text; '' if it isn't decodable text."""
    blob = blob[:_MAX_BLOB]
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(blob + "=" * (-len(blob) % 4))
        except (binascii.Error, ValueError):
            continue
        if (t := printable_text(_inflate(raw))):
            return t
    return ""


def decode_hex(blob: str) -> str:
    """Best-effort decode of a hex run to text; '' if it isn't decodable text."""
    blob = blob[:_MAX_BLOB]
    if len(blob) % 2:
        blob = blob[:-1]
    try:
        return printable_text(_inflate(bytes.fromhex(blob)))
    except ValueError:
        return ""


class Decoded(NamedTuple):
    text: str          # every printable decoding, joined ('' if nothing decoded)
    exhausted: bool    # the budget ran out with blobs left undecoded


def _not_encoded(blob: str) -> bool:
    # A long single-case run of letters is a word ("internationalization"), not encoded
    # data: real base64 of anything mixes case or carries digits. Skipped without cost, so
    # prose doesn't spend the budget.
    return blob.isalpha() and (blob.islower() or blob.isupper())


def decode_obfuscated_detail(text: str, percent: bool = True) -> Decoded:
    """Decode every base64/hex blob, then the blobs inside what decoded, up to _MAX_DEPTH
    levels, within one _BUDGET of encoded characters; plus (with `percent`) a
    percent-decoded view. Meant only to be re-scanned for attack phrases / PII / secrets an
    encoded blob is hiding — never surfaced verbatim."""
    blobs = _decode_blobs(text)
    if percent and "%" in text:
        try:
            dec = urllib.parse.unquote(text)
            if dec != text:
                return Decoded("\n".join(p for p in (blobs.text, dec) if p), blobs.exhausted)
        except (ValueError, UnicodeDecodeError):
            pass
    return blobs


@functools.lru_cache(maxsize=16)       # several detectors decode the same item's text
def _decode_blobs(text: str) -> Decoded:
    out: list[str] = []
    budget = _BUDGET
    exhausted = False
    level = [text]
    for _depth in range(_MAX_DEPTH):
        nxt: list[str] = []
        for src in level:
            for rx, dec in ((_B64_RE, decode_b64), (_HEX_RE, decode_hex)):
                for m in rx.finditer(src):
                    blob = m.group(0)
                    if _not_encoded(blob):
                        continue
                    cost = min(len(blob), _MAX_BLOB)
                    if cost > budget or len(blob) > _MAX_BLOB:
                        exhausted = True
                        if cost > budget:
                            continue
                    budget -= cost
                    if (d := dec(blob)):
                        out.append(d)
                        nxt.append(d)
        if not nxt:
            break
        level = nxt
    else:
        # decoded text at the last level that itself still holds a blob is left unread
        exhausted = exhausted or any(_B64_RE.search(t) or _HEX_RE.search(t) for t in level)
    return Decoded("\n".join(out), exhausted)


def decode_obfuscated(text: str) -> str:
    """decode_obfuscated_detail's text alone."""
    return decode_obfuscated_detail(text).text
