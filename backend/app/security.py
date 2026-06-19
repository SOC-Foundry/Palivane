"""Auth crypto primitives — password hashing and signed tokens.

Stdlib only: PBKDF2-HMAC-SHA256 for passwords and a minimal, hardened HS256 JWT for
session tokens. This keeps the dependency surface small and the whole thing offline-
testable. For a high-security production deployment you may prefer argon2id (passwords)
and a vetted JWT library (PyJWT) — the call sites here are isolated so swapping is easy.

Hardening notes for the token code:
- Only the `HS256` algorithm is accepted on verify; `none` and asymmetric algs are
  rejected, closing the classic alg-confusion / alg=none bypasses.
- Signatures and password hashes are compared with `hmac.compare_digest`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from .config import settings

# --- passwords ------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


# --- API keys (long-lived machine credentials) ----------------------------------------

API_KEY_PREFIX = "ak_"
_PREFIX_LEN = 11  # "ak_" + 8 chars, stored for display/lookup


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return (plaintext, lookup_prefix, sha256_hash). Only the hash is stored."""
    token = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return token, token[:_PREFIX_LEN], hash_token(token)


def looks_like_api_key(token: str) -> bool:
    return token.startswith(API_KEY_PREFIX)


# --- tokens (HS256 JWT) ---------------------------------------------------------------

_DEV_FALLBACK_KEY = "dev-insecure-key-change-me"


def _secret() -> bytes:
    return (settings.auth_secret_key or _DEV_FALLBACK_KEY).encode()


def using_insecure_key() -> bool:
    return not settings.auth_secret_key


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(signing_input: bytes) -> str:
    return _b64e(hmac.new(_secret(), signing_input, hashlib.sha256).digest())


def create_token(claims: dict, ttl: int | None = None) -> str:
    ttl = settings.auth_token_ttl if ttl is None else ttl
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + ttl}
    header = {"alg": "HS256", "typ": "JWT"}
    segs = [
        _b64e(json.dumps(header, separators=(",", ":")).encode()),
        _b64e(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segs).encode()
    segs.append(_sign(signing_input))
    return ".".join(segs)


class TokenError(Exception):
    """Raised when a token is malformed, mis-signed, wrong-alg, or expired."""


def decode_token(token: str) -> dict:
    try:
        header_b64, payload_b64, sig = token.split(".")
    except ValueError:
        raise TokenError("malformed token")

    try:
        header = json.loads(_b64d(header_b64))
    except (ValueError, json.JSONDecodeError):
        raise TokenError("bad header")
    if header.get("alg") != "HS256":  # reject none/alg-confusion
        raise TokenError("unsupported algorithm")

    expected = _sign(f"{header_b64}.{payload_b64}".encode())
    if not hmac.compare_digest(expected, sig):
        raise TokenError("bad signature")

    try:
        payload = json.loads(_b64d(payload_b64))
    except (ValueError, json.JSONDecodeError):
        raise TokenError("bad payload")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise TokenError("token expired")
    return payload
