"""Symmetric encryption for secrets stored at rest (per-tenant upstream provider keys).

Uses Fernet (AES-CBC + HMAC, authenticated) with a key derived from WARDEN_ENCRYPTION_KEY,
falling back to WARDEN_SECRET_KEY. Deriving from the existing secret means a self-host
gets encryption for free; set a dedicated WARDEN_ENCRYPTION_KEY to rotate independently.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from .config import settings, _env


def _fernet() -> Fernet:
    secret = (_env("PALIVANE_ENCRYPTION_KEY", "WARDEN_ENCRYPTION_KEY") or settings.auth_secret_key
              or "dev-insecure-change-me").encode()
    # Fernet needs a 32-byte urlsafe-base64 key; derive one deterministically.
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret).digest()))


def encrypt(plaintext: str) -> str:
    """Encrypt a secret for storage. Empty in → empty out."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Decrypt a stored secret. Returns "" if the token is empty or undecryptable
    (e.g. the encryption key was rotated) — callers treat that as "not configured"."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


# --- reversible field encryption for stored content ----------------------------------
#
# A tagged wrapper so a column can hold a mix of plaintext (legacy / feature off) and
# ciphertext (feature on) rows: `seal` only encrypts, `unseal` decrypts only tagged values.

_ENC_PREFIX = "enc:v1:"


def seal(text: str) -> str:
    """Encrypt text for storage, tagged so `unseal` can recognize it. Empty stays empty."""
    if not text:
        return text
    return _ENC_PREFIX + encrypt(text)


def unseal(text):
    """Decrypt a sealed value; pass anything else (plaintext / non-str) through unchanged."""
    if isinstance(text, str) and text.startswith(_ENC_PREFIX):
        return decrypt(text[len(_ENC_PREFIX):])
    return text


# --- per-tenant envelope encryption (BYOK-style) -------------------------------------
#
# Each tenant gets its own random data key (DEK), wrapped by the master key (KEK derived
# above) and stored on the tenant row. Content is sealed under the tenant's DEK, tagged
# `enc:v2:`. Benefit over one global key: a DB breach without the KEK yields nothing, no
# single key unlocks every tenant, and a tenant's content can be revoked by dropping its
# wrapped DEK. Legacy `enc:v1:` (global-key) values still decrypt via unseal_with().

_ENC_PREFIX_V2 = "enc:v2:"


def new_dek() -> str:
    """A fresh per-tenant data key (urlsafe-base64 Fernet key), as a str for storage."""
    return Fernet.generate_key().decode()


def wrap_dek(dek: str) -> str:
    """Encrypt a tenant DEK under the master KEK for storage on the tenant row."""
    return _fernet().encrypt(dek.encode()).decode()


def unwrap_dek(wrapped: str) -> str | None:
    try:
        return _fernet().decrypt(wrapped.encode()).decode()
    except (InvalidToken, ValueError):
        return None


def seal_with(dek: str, text: str) -> str:
    """Encrypt `text` under a tenant DEK, tagged enc:v2:. Empty stays empty."""
    if not text:
        return text
    return _ENC_PREFIX_V2 + Fernet(dek.encode()).encrypt(text.encode()).decode()


def unseal_with(text, dek: str | None):
    """Decrypt any sealed value: enc:v2: needs the tenant DEK; enc:v1: uses the global key;
    anything else passes through. Returns a marker if a v2 value can't be opened."""
    if not isinstance(text, str):
        return text
    if text.startswith(_ENC_PREFIX_V2):
        if not dek:
            return "[content unavailable — tenant key missing]"
        try:
            return Fernet(dek.encode()).decrypt(text[len(_ENC_PREFIX_V2):].encode()).decode()
        except (InvalidToken, ValueError):
            return "[content unavailable — undecryptable]"
    if text.startswith(_ENC_PREFIX):
        return decrypt(text[len(_ENC_PREFIX):])
    return text
