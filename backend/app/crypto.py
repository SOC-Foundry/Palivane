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

from .config import settings


def _fernet() -> Fernet:
    secret = (os.getenv("WARDEN_ENCRYPTION_KEY") or settings.auth_secret_key
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
