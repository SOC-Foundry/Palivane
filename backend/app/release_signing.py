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

Two signatures. `manifest.sig` (v1) covers the {name: sha256} map, which every client
verifies. `manifest.sig2` (v2) covers that map plus `issued`, a release timestamp that the
manifest also carries. A client that has seen v2 refuses a release older than the newest
it has accepted, and refuses a manifest without v2: replaying an older signed release, or
stripping the v2 signature, no longer rolls it back.

Where the signatures come from, in order:
  1. A bundle signed at BUILD time (release/signed-manifest.json, written by
     backend/tools/release_sign.py with a Cloud KMS key in the deploy pipeline). The
     private key never enters the running service, so compromising the backend can't
     sign a malicious release. The bundle is served only while its digest matches the
     files this image serves.
  2. `PALIVANE_RELEASE_SIGNING_KEY` (PEM) in the environment: self-hosts and dev. The
     production service no longer has it once the deploy signs with KMS. When it's unset the deployment serves an *unsigned*
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
import logging
import os

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
    """Whether this deployment serves signed releases (install.sh then fails closed)."""
    return bool(_signing_key_pem()) or _bundle() is not None


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
    from .release_files import served_files
    problem = key_pair_problem() or bundle_problem(served_files())
    if not problem:
        return
    if prod:
        raise RuntimeError(problem)
    log.warning(problem)


_log = logging.getLogger("palivane.release_signing")

# backend/release/signed-manifest.json in the repo; /app/release/ in the image.
BUNDLE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "release", "signed-manifest.json")
_BUNDLE: dict | None = None
_BUNDLE_LOADED = False


def _bundle() -> dict | None:
    """The build-time signature bundle, or None when this image carries none."""
    global _BUNDLE, _BUNDLE_LOADED
    if not _BUNDLE_LOADED:
        _BUNDLE_LOADED = True
        try:
            with open(BUNDLE_PATH) as f:
                b = json.load(f)
            if all(isinstance(b.get(k), str) for k in ("files_digest", "sig", "sig2")) \
                    and isinstance(b.get("issued"), int):
                _BUNDLE = b
            else:
                _log.error("release bundle %s is malformed; ignoring it", BUNDLE_PATH)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            _log.error("release bundle %s is unreadable; ignoring it", BUNDLE_PATH)
    return _BUNDLE


def _bundle_for(files: dict) -> dict | None:
    """The bundle, if it signs exactly these files."""
    b = _bundle()
    if b and b["files_digest"] == hashlib.sha256(canonical_files_digest(files)).hexdigest():
        return b
    return None


def bundle_problem(files: dict) -> str | None:
    """Why this image's signature bundle can't be served, or None (also None with no bundle).
    Checked at startup next to key_pair_problem: a bundle that doesn't match the files or
    doesn't verify under the pinned key would make every client refuse every update."""
    b = _bundle()
    if b is None:
        return None
    if _bundle_for(files) is None:
        return ("release/signed-manifest.json was signed for different files than this image "
                "serves (the CLI changed after signing), so the release would go out unsigned "
                "and every client would refuse it. Re-run backend/tools/release_sign.py.")
    if not (verify_files(files, b["sig"]) and verify_release(files, b["issued"], b["sig2"])):
        return ("release/signed-manifest.json does not verify under the key the installer "
                "pins, so every client would refuse it. The KMS key that signed it is not "
                "the pinned release key.")
    return None


def _env_issued(files: dict) -> int:
    """`issued` for a release signed from the environment: the newest served file's mtime.
    The same for every instance of one image (unlike a process start time, which would
    make instances look like rollbacks of each other), and later for a later release."""
    from .release_files import ALLOW, resolve
    newest = 0
    for name in files:
        path = resolve(ALLOW.get(name, ""))
        if path:
            try:
                newest = max(newest, int(os.stat(path).st_mtime))
            except OSError:
                pass
    return newest


def release_issued(files: dict) -> int | None:
    """The `issued` the manifest carries (and v2 signs), or None when nothing signs."""
    b = _bundle_for(files)
    if b:
        return b["issued"]
    return _env_issued(files) if _signing_key_pem() else None


def canonical_release_digest(files: dict, issued: int) -> bytes:
    """What v2 signs: {"files": {name: sha256}, "issued": N} as canonical JSON."""
    hashes = {name: meta["sha256"] for name, meta in files.items()}
    return json.dumps({"files": hashes, "issued": int(issued)},
                      separators=(",", ":"), sort_keys=True).encode()


def _sign(message: bytes) -> str | None:
    pem = _signing_key_pem()
    if not pem:
        return None
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(pem.encode(), password=None)
    return base64.b64encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).decode()


def _verify(message: bytes, signature_b64: str, pubkey_pem: str | None) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        pub = load_pem_public_key((pubkey_pem or release_pubkey_pem()).encode())
        pub.verify(base64.b64decode(signature_b64), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_release(files: dict) -> str | None:
    """The v2 signature (base64 DER) over files + issued, or None when nothing signs."""
    b = _bundle_for(files)
    if b:
        return b["sig2"]
    issued = release_issued(files)
    return _sign(canonical_release_digest(files, issued)) if issued is not None else None


def verify_release(files: dict, issued: int, signature_b64: str,
                   pubkey_pem: str | None = None) -> bool:
    return _verify(canonical_release_digest(files, issued), signature_b64, pubkey_pem)


def canonical_files_digest(files: dict) -> bytes:
    """The exact bytes that get signed/verified: the {name: sha256} map as canonical JSON
    (sorted keys, no whitespace). Only names + hashes — nothing deployment-specific — so
    the signature is identical for the same release everywhere."""
    hashes = {name: meta["sha256"] for name, meta in files.items()}
    return json.dumps(hashes, separators=(",", ":"), sort_keys=True).encode()


def sign_files(files: dict) -> str | None:
    """Base64 ECDSA-P256/SHA-256 signature (DER) over the canonical files digest, or None
    if nothing signs (the deployment then serves an unsigned manifest). The DER encoding is
    exactly what `openssl dgst -sha256 -verify` consumes on the installer side."""
    b = _bundle_for(files)
    if b:
        return b["sig"]
    return _sign(canonical_files_digest(files))


def verify_files(files: dict, signature_b64: str, pubkey_pem: str | None = None) -> bool:
    """True iff `signature_b64` is a valid signature over `files` under the pinned key.
    Used by tests and any client that wants to verify in-process."""
    return _verify(canonical_files_digest(files), signature_b64, pubkey_pem)


def sha256_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
