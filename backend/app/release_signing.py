"""Release signing for the served CLI (supply-chain integrity for `curl … | install.sh`).

The installer downloads plain scripts over HTTPS and executes them. TLS proves *who*
served them; it does not prove the bytes match a release the vendor actually built. This
module closes that gap with an ECDSA P-256 / SHA-256 signature over the manifest of
per-file SHA-256 hashes, so the installer can verify every component before it runs.

Scheme note: the vendor *license* (`licensing.py`) uses Ed25519, but the release signature
must be verifiable by the installer with the stock `openssl dgst -verify` CLI on any
customer machine — and Ed25519 verification through the openssl CLI is version-fragile
(`pkeyutl -rawin` quirks). ECDSA P-256 + SHA-256 verifies cleanly and identically across
every openssl/libressl, so the shell installer stays portable.

What is signed: the canonical `{name: sha256}` map of the served scripts — deterministic
from the shipped code and identical across deployments of the same release, so a release
is signed once and any instance can serve the signature. `base_url`/`self_update` (which
vary per deployment) are deliberately NOT signed.

Server side: the private key comes from `PALIVANE_RELEASE_SIGNING_KEY` (PEM), mirroring
`PALIVANE_LICENSE_SIGNING_KEY`; in production it lives in Secret Manager
(`palivane-release-signing-key`). When it's unset the deployment serves an *unsigned*
manifest and the generated installer warns-but-proceeds — so nothing breaks before the
key is provisioned; enforcement flips on automatically once it is.

Client side: the generated `install.sh` bakes this deployment's public key and verifies
`manifest.sig` against it, then checks each downloaded file's SHA-256. A fork/self-host
with its own key bakes its own public half (`PALIVANE_RELEASE_PUBKEY`); the pinned key is
the trust anchor, so a MITM that can rewrite the served files still can't forge the sig.
"""
from __future__ import annotations

import base64
import hashlib
import json

from .config import _env

# TachTech's release-signing public key (ECDSA P-256). The matching private key is the
# vendor's alone (Secret Manager: palivane-release-signing-key). Override for forks/tests
# via PALIVANE_RELEASE_PUBKEY.
VENDOR_RELEASE_PUBKEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpJPi60i2koK+QeU/hJOpMnCH1TIQ
DOr+Qjb3j446+61ofaZGRQNI68sEG6g+N7z4f78mArB2tshax27gy41enA==
-----END PUBLIC KEY-----
"""


def release_pubkey_pem() -> str:
    """The public key the installer pins. Deployment override wins so a self-host verifies
    against its own signing key."""
    return _env("PALIVANE_RELEASE_PUBKEY", "").strip() or VENDOR_RELEASE_PUBKEY_PEM


def _signing_key_pem() -> str:
    return _env("PALIVANE_RELEASE_SIGNING_KEY", "").strip()


def signing_enabled() -> bool:
    return bool(_signing_key_pem())


def canonical_files_digest(files: dict) -> bytes:
    """The exact bytes that get signed/verified: the {name: sha256} map as canonical JSON
    (sorted keys, no whitespace). Only names + hashes — nothing deployment-specific — so
    the signature is identical for the same release everywhere."""
    hashes = {name: meta["sha256"] for name, meta in files.items()}
    return json.dumps(hashes, separators=(",", ":"), sort_keys=True).encode()


def sign_files(files: dict) -> str | None:
    """Base64 ECDSA-P256/SHA-256 signature (DER) over the canonical files digest, or None
    if no key is set (the deployment then serves an unsigned manifest). The DER encoding is
    exactly what `openssl dgst -sha256 -verify` consumes on the installer side."""
    pem = _signing_key_pem()
    if not pem:
        return None
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(pem.encode(), password=None)
    sig = key.sign(canonical_files_digest(files), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def verify_files(files: dict, signature_b64: str, pubkey_pem: str | None = None) -> bool:
    """True iff `signature_b64` is a valid signature over `files` under the pinned key.
    Used by tests and any client that wants to verify in-process."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        pub = load_pem_public_key((pubkey_pem or release_pubkey_pem()).encode())
        pub.verify(base64.b64decode(signature_b64), canonical_files_digest(files),
                   ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sha256_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
