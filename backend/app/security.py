"""Auth crypto primitives — password hashing and signed tokens.

Passwords use **argon2id** (argon2-cffi); legacy PBKDF2-HMAC-SHA256 hashes are still
verified and transparently upgraded on next login. Session tokens are a minimal, hardened
HS256 JWT (a vetted lib like PyJWT is a drop-in if preferred — the call sites are isolated).

Hardening notes for the token code:
- Only the `HS256` algorithm is accepted on verify; `none` and asymmetric algs are
  rejected, closing the classic alg-confusion / alg=none bypasses.
- Signatures and legacy password hashes are compared with `hmac.compare_digest`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error

from .config import settings

# --- passwords ------------------------------------------------------------------------

_ph = PasswordHasher()   # argon2id with sensible defaults
# Precomputed argon2 hash to verify against on a user-miss, so a wrong email costs the
# same time as a wrong password (no user-enumeration via timing).
DUMMY_PASSWORD_HASH = _ph.hash("warden-timing-placeholder")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("$argon2"):
        try:
            return _ph.verify(stored, password)
        except Argon2Error:
            return False
    # Legacy PBKDF2 hashes (pre-argon2) — still accepted; upgraded on login.
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


def needs_rehash(stored: str) -> bool:
    """True if the stored hash isn't current argon2id (legacy or outdated params)."""
    if not stored.startswith("$argon2"):
        return True
    try:
        return _ph.check_needs_rehash(stored)
    except Argon2Error:
        return True


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


AGENT_TOKEN_PREFIX = "ag_"


def generate_agent_token() -> tuple[str, str, str]:
    """Return (plaintext, lookup_prefix, sha256_hash) for a per-agent identity credential."""
    token = AGENT_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, token[:_PREFIX_LEN], hash_token(token)


def looks_like_agent_token(token: str) -> bool:
    return (token or "").startswith(AGENT_TOKEN_PREFIX)


def looks_like_jwt(token: str) -> bool:
    """A compact JWS: three base64url segments, header starting with the `eyJ` marker."""
    t = token or ""
    return t.startswith("eyJ") and t.count(".") == 2


def jwt_unverified_claims(token: str) -> dict:
    """Best-effort decode of a JWT's payload WITHOUT signature verification — only to read
    `iss` so we can pick the tenant whose JWKS to verify against. Never trust these claims."""
    import base64
    import json
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


ENROLL_TOKEN_PREFIX = "et_"


def generate_enrollment_token() -> tuple[str, str, str]:
    """Return (plaintext, lookup_prefix, sha256_hash) for a device-enrollment token."""
    token = ENROLL_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, token[:_PREFIX_LEN], hash_token(token)


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
