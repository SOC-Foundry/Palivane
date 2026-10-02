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
key is provisioned; enforcement flips on automatically once it is. That flip is why
`key_pair_problem` exists: the service refuses to boot (in production) if the key it signs
with is not the one the installer pins.

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

# Palivane's release-signing public key (ECDSA P-256). The matching private key lives in
# Secret Manager as palivane-release-signing-key and nowhere else. Override for
# forks/self-hosts via PALIVANE_RELEASE_PUBKEY.
#
# The key this replaced had no private half anywhere — which is why signing was never
# switched on and /cli/manifest.sig answered 404 in production, while the docs described
# an installer that fails closed. Rotating it is safe because /install.sh is generated per
# request (distribution.py) and bakes in whatever key is current, so the documented
# `curl … | bash` flow always gets this one.
VENDOR_RELEASE_PUBKEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtwIOdXmgRU12/7oDPzpkLqrud1DN
s2ngn344uoGU+MF5HUF7gFG2emj+UG3aPvm5Jbh+ggQdxs9R7ZZ1PwoP9Q==
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


def _spki_der(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def _fingerprint(public_key) -> str:
    """Short, non-secret name for a public key, so a message can say WHICH two keys disagree
    without quoting either one."""
    return "sha256:" + hashlib.sha256(_spki_der(public_key)).hexdigest()[:16]


def key_pair_problem() -> str | None:
    """Why the configured signing key cannot work with the key the installer pins, or None.

    None when signing is off (nothing is signed, so nothing can disagree) and when the
    signing key's public half IS the pinned key. Compared as keys, not as PEM text, so
    wrapping or a trailing newline from a secret store does not read as a different key.

    "Enforcement flips on automatically once the key is provisioned" (module docstring) is
    the right default, and it has one sharp edge: the flip happens whenever the secret
    exists and is bound, not when the matching public key reaches the code. On 2026-10-01
    the secret was created for a change that had not merged, the next deploy bound it, and
    the service signed with a key the installer did not pin. The installer is fail-closed
    on a signature that does not verify, so every install aborted for 19 minutes, and
    nothing in the service, the deploy or the metrics said so.

    The service holds both halves, so it can check them itself, and the message names the
    two keys by fingerprint and never quotes either."""
    pem = _signing_key_pem()
    if not pem:
        return None
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key)

    try:
        priv = load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return ("PALIVANE_RELEASE_SIGNING_KEY is set but is not a readable, unencrypted PEM "
                "private key, so the manifest cannot be signed. Store the key exactly as "
                "`openssl ecparam -name prime256v1 -genkey -noout` wrote it.")
    if not (isinstance(priv, ec.EllipticCurvePrivateKey) and isinstance(priv.curve, ec.SECP256R1)):
        return ("PALIVANE_RELEASE_SIGNING_KEY is not an ECDSA P-256 key. The installer "
                "verifies with the stock openssl CLI against P-256, so any other key "
                "produces signatures every installer rejects.")
    try:
        pinned = load_pem_public_key(release_pubkey_pem().encode())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return ("The pinned release public key (VENDOR_RELEASE_PUBKEY_PEM, or "
                "PALIVANE_RELEASE_PUBKEY when it is set) is not a readable PEM public key, "
                "so installers cannot verify anything PALIVANE_RELEASE_SIGNING_KEY signs.")
    if _spki_der(priv.public_key()) != _spki_der(pinned):
        return (f"PALIVANE_RELEASE_SIGNING_KEY signs with a key "
                f"({_fingerprint(priv.public_key())}) that is not the one the installer pins "
                f"({_fingerprint(pinned)}). The installer is fail-closed on a signature that "
                f"does not verify, so every install would abort. Make them the same key: "
                f"set VENDOR_RELEASE_PUBKEY_PEM in release_signing.py (or "
                f"PALIVANE_RELEASE_PUBKEY) to the signing key's public half, or remove the "
                f"secret so releases go out unsigned.")
    return None


def enforce_key_pair(prod: bool, log) -> None:
    """Startup gate, called from main.lifespan. A production-shaped deployment refuses to
    boot on a key pair that would break every install, the same split the lifespan already
    uses for a weak PALIVANE_SECRET_KEY; SQLite dev only warns.

    On Cloud Run, refusing to boot is the safe outcome and not an outage: a revision that
    fails its startup probe never receives traffic, so the previous revision keeps serving
    and the deploy fails instead of the installer."""
    problem = key_pair_problem()
    if not problem:
        return
    if prod:
        raise RuntimeError(problem)
    log.warning(problem)


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
