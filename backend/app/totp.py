"""TOTP (RFC 6238) + recovery codes for MFA — standard library only.

No external dependency: HOTP is HMAC-SHA1 over a time counter. Secrets are base32; the
provisioning URI is the standard `otpauth://` format any authenticator app accepts.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

_STEP = 30      # seconds per code
_DIGITS = 6
_WINDOW = 1     # accept the adjacent step each side (clock skew)


def generate_secret() -> str:
    """A fresh base32 TOTP secret (160 bits)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * ((-len(secret_b32)) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** _DIGITS)
    return str(code).zfill(_DIGITS)


def verify(secret_b32: str, code: str) -> bool:
    """Constant-time-ish check of a 6-digit code against the current ±1 time windows."""
    return verify_step(secret_b32, code) is not None


def verify_step(secret_b32: str, code: str) -> int | None:
    """Like verify() but returns the matched time-step counter (or None). The caller
    persists the last accepted step and rejects any step <= it, so a code can't be
    replayed within its validity window (RFC 6238 single-use-per-step)."""
    code = (code or "").strip()
    if not secret_b32 or not code.isdigit():
        return None
    now = int(time.time() // _STEP)
    matched = None
    for i in range(-_WINDOW, _WINDOW + 1):
        if hmac.compare_digest(_hotp(secret_b32, now + i), code):
            matched = now + i   # no early-exit: keep the compare count constant
    return matched


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Warden") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret_b32}&issuer={quote(issuer)}")


# --- recovery codes -------------------------------------------------------------------

def generate_recovery_codes(n: int = 10) -> list[str]:
    """Human-friendly one-time codes (shown once)."""
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()


def consume_recovery(stored_hashes: list[str], code: str) -> list[str] | None:
    """If `code` matches a stored hash, return the remaining hashes (consumed); else None.
    Constant-time compare against each stored hash (no early-exit on the first match)."""
    import hmac
    h = hash_code(code)
    matched = None
    for stored in (stored_hashes or []):
        if hmac.compare_digest(h, stored):
            matched = stored
    if matched is None:
        return None
    return [x for x in stored_hashes if x != matched]
