#!/usr/bin/env python3
"""Sign the CLI release manifest at build time with a Cloud KMS key.

The deploy pipeline runs this before building the image (deploy/cloudrun/deploy.sh, when
RELEASE_KMS_KEY_VERSION is set). It computes the exact file set the backend serves
(app/release_files.py), has Cloud KMS sign the v1 and v2 messages (app/release_signing.py),
checks both signatures against the key the installer pins, and writes
backend/release/signed-manifest.json, which the image carries and the backend serves. The
private key stays in KMS: neither this runner's disk nor the running service ever holds it.

    python3 backend/tools/release_sign.py \\
        --kms-key-version projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N

Stdlib + the gcloud and openssl CLIs only (the deploy runner has no app dependencies).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BACKEND, "release", "signed-manifest.json")
_VERSION_RE = re.compile(
    r"^projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)/cryptoKeyVersions/(\d+)$")


def _release_files():
    path = os.path.join(BACKEND, "app", "release_files.py")
    spec = importlib.util.spec_from_file_location("palivane_release_files", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pinned_pubkey() -> str:
    """The key the installer pins: PALIVANE_RELEASE_PUBKEY when the deploy sets it (a
    self-host), else VENDOR_RELEASE_PUBKEY_PEM from app/release_signing.py."""
    pem = os.environ.get("PALIVANE_RELEASE_PUBKEY", "").strip()
    if pem:
        return pem + "\n"
    src = open(os.path.join(BACKEND, "app", "release_signing.py")).read()
    m = re.search(r'VENDOR_RELEASE_PUBKEY_PEM = """(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)',
                  src, re.S)
    if not m:
        sys.exit("release_sign: VENDOR_RELEASE_PUBKEY_PEM not found in release_signing.py")
    return m.group(1) + "\n"


def messages(files: dict, issued: int) -> tuple[bytes, bytes]:
    """(v1, v2) exactly as release_signing.canonical_files_digest/_release_digest build them."""
    hashes = {n: m["sha256"] for n, m in files.items()}
    v1 = json.dumps(hashes, separators=(",", ":"), sort_keys=True).encode()
    v2 = json.dumps({"files": hashes, "issued": int(issued)},
                    separators=(",", ":"), sort_keys=True).encode()
    return v1, v2


def kms_sign(version: str, message: bytes, work: str) -> bytes:
    m = _VERSION_RE.match(version)
    if not m:
        sys.exit("release_sign: --kms-key-version must be a full cryptoKeyVersions resource name")
    project, location, ring, key, num = m.groups()
    msg, sig = os.path.join(work, "msg"), os.path.join(work, "sig.der")
    with open(msg, "wb") as f:
        f.write(message)
    subprocess.run(["gcloud", "kms", "asymmetric-sign", "--project", project,
                    "--location", location, "--keyring", ring, "--key", key,
                    "--version", num, "--digest-algorithm", "sha256",
                    "--input-file", msg, "--signature-file", sig], check=True)
    with open(sig, "rb") as f:
        return f.read()


def openssl_verifies(message: bytes, der: bytes, pubkey_pem: str, work: str) -> bool:
    paths = {}
    for name, blob in (("pub.pem", pubkey_pem.encode()), ("v.der", der), ("v.msg", message)):
        paths[name] = os.path.join(work, name)
        with open(paths[name], "wb") as f:
            f.write(blob)
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", paths["pub.pem"],
                        "-signature", paths["v.der"], paths["v.msg"]],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--kms-key-version", required=True)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    files = _release_files().served_files()
    if not files:
        sys.exit("release_sign: no served files found (run from a full checkout)")
    issued = int(time.time())
    v1, v2 = messages(files, issued)
    pub = pinned_pubkey()
    with tempfile.TemporaryDirectory(prefix="palivane-sign-") as work:
        sig1 = kms_sign(args.kms_key_version, v1, work)
        sig2 = kms_sign(args.kms_key_version, v2, work)
        for label, msg, sig in (("v1", v1, sig1), ("v2", v2, sig2)):
            if not openssl_verifies(msg, sig, pub, work):
                sys.exit(f"release_sign: the KMS {label} signature does not verify under the "
                         "key the installer pins. That KMS key is not the pinned release key; "
                         "every client would refuse this release. Not writing a bundle.")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    bundle = {"issued": issued,
              "files_digest": hashlib.sha256(v1).hexdigest(),
              "sig": base64.b64encode(sig1).decode(),
              "sig2": base64.b64encode(sig2).decode(),
              "files": len(files)}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")
    print(f"release_sign: signed {len(files)} files, issued {issued}, wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
