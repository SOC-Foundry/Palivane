"""Symmetric encryption for secrets stored at rest (per-tenant upstream provider keys).

Uses Fernet (AES-CBC + HMAC, authenticated) with a key derived from PALIVANE_ENCRYPTION_KEY,
falling back to PALIVANE_SECRET_KEY. Deriving from the existing secret means a self-host
gets encryption for free; set a dedicated PALIVANE_ENCRYPTION_KEY to rotate independently.

The key is derived with HKDF-SHA256 (a real KDF with domain-separating salt/info). A
MultiFernet keeps the older bare-SHA256 derivation as a *decrypt-only* fallback, so secrets
written before this change still open; anything re-encrypted is upgraded to the HKDF key.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings, _env


def _secret_bytes() -> bytes:
    return (_env("PALIVANE_ENCRYPTION_KEY") or settings.auth_secret_key
            or "dev-insecure-change-me").encode()


def _fernet() -> MultiFernet:
    # Fernet needs a 32-byte urlsafe-base64 key. Primary: HKDF-SHA256. Fallback (decrypt
    # only): the legacy unsalted SHA-256 so existing ciphertext keeps working.
    secret = _secret_bytes()
    hkdf_key = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=b"palivane.crypto.hkdf.v1", info=b"secret-at-rest").derive(secret)
    legacy_key = hashlib.sha256(secret).digest()
    return MultiFernet([Fernet(base64.urlsafe_b64encode(hkdf_key)),
                        Fernet(base64.urlsafe_b64encode(legacy_key))])


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

# --- per-tenant SECRETS ---------------------------------------------------------------
#
# Content already rides the v2 envelope. Stored credentials did not: provider API keys,
# judge BYOK keys, OIDC client secrets, SIEM tokens and SaaS-connector credentials were
# all sealed with the one deployment key, so a single KEK compromise exposed every
# tenant's. The connector credentials are the sharp end of that, since a Google Workspace
# entry holds a domain-wide-delegation service-account key.
#
# These are separate from seal_with/unseal_with for one reason: on failure a secret must
# read as "not configured" (""), the same as a rotated key has always produced, whereas
# content returns a human-readable marker for display. Returning a marker string where a
# caller expects a credential would send the marker to a provider as an API key.
#
# Three storage shapes have to be readable, because migration is lazy (a value is only
# rewritten under the tenant DEK when it is next saved):
#   enc:v2:<tok>  tenant DEK
#   enc:v1:<tok>  global key, written by seal()
#   <tok>         global key, bare, written by encrypt() - the original shape

def seal_secret(dek: str | None, plaintext: str) -> str:
    """Encrypt a credential under the tenant DEK when there is one, else the global key."""
    if not plaintext:
        return ""
    if dek:
        return _ENC_PREFIX_V2 + Fernet(dek.encode()).encrypt(plaintext.encode()).decode()
    return encrypt(plaintext)


def unseal_secret(stored, dek: str | None, legacy_plaintext: bool = False) -> str:
    """Decrypt a stored credential. "" when it cannot be opened, which every caller
    already treats as "not configured".

    `legacy_plaintext` picks what an UNPREFIXED value means, and the two column families
    disagree, so this cannot be one rule:

      seal()/unseal() columns (siem_token, siem_s3_secret) predate sealing, so an
      unprefixed value there is genuine plaintext and must pass through untouched.
      Deployments still hold rows written before those columns were ever encrypted.

      encrypt()/decrypt() columns (key_encrypted, credentials_enc, client_secret) were
      always ciphertext, so an unprefixed value that will not decrypt is a rotated key,
      and "" is the long-standing answer.
    """
    if not isinstance(stored, str) or not stored:
        return ""
    if stored.startswith(_ENC_PREFIX_V2):
        if not dek:
            return ""
        try:
            return Fernet(dek.encode()).decrypt(stored[len(_ENC_PREFIX_V2):].encode()).decode()
        except (InvalidToken, ValueError):
            return ""
    if stored.startswith(_ENC_PREFIX):
        return decrypt(stored[len(_ENC_PREFIX):])
    if legacy_plaintext:
        return decrypt(stored) or stored
    return decrypt(stored)


def tenant_dek(tenant, db) -> str | None:
    """The tenant's unwrapped data key, minting and storing a wrapped one on first use.
    None when there is no tenant, so callers fall back to the global key."""
    if tenant is None:
        return None
    if not tenant.dek_wrapped:
        dek = new_dek()
        tenant.dek_wrapped = wrap_dek(dek)
        db.commit()
        return dek
    return unwrap_dek(tenant.dek_wrapped)


# Deliberately still on the global key: user MFA (TOTP) secrets. They are per-USER, and
# they are read during login, before the caller is authenticated, so moving them to the
# owning tenant's DEK adds a Tenant load and an unwrap to the auth path for a secret whose
# blast radius differs from a tenant credential. Worth doing, but as its own change with
# its own thinking about the login path, not folded in here.


def tenant_dek_readonly(tenant) -> str | None:
    """Unwrap an existing tenant DEK without a session. Minting one needs db.commit(),
    but opening an already-provisioned key does not, so background paths (the archive
    flusher, anything off the request path) can still read enc:v2: values. Returns None
    when the tenant has no DEK yet, which means nothing was ever sealed under one."""
    if tenant is None or not getattr(tenant, "dek_wrapped", ""):
        return None
    return unwrap_dek(tenant.dek_wrapped)


def dek_for(db, tenant_id) -> str | None:
    """tenant_dek by id, for rows that carry tenant_id rather than the Tenant itself."""
    if not tenant_id:
        return None
    from .models import Tenant
    return tenant_dek(db.get(Tenant, tenant_id), db)
