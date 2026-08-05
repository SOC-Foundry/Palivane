"""Vendor-signed licenses for self-hosted Palivane (Team / Enterprise tiers).

On the hosted SaaS the license IS the `tenant.plan` column (vendor ops runs
`python -m app.users set-plan` when a deal closes). Self-hosted deployments can't be
reached that way, so they carry a **license file**: an Ed25519-signed blob the vendor
issues, which lifts every tenant on that instance to the licensed plan (and seat count)
for as long as it's valid. No license = the Free tier, which is fully functional.

    WDN1.<b64url(payload-json)>.<b64url(ed25519-sig)>

The payload is canonical JSON: {v, id, org, plan, seats, issued, expires}. The signature
covers the exact payload bytes, so any edit (plan bump, seat bump, expiry push) breaks it.

Vendor side (TachTech) — this module doubles as the issuing CLI:

    python -m app.licensing keygen --out vendor-license-key.pem      # once, keep PRIVATE
    python -m app.licensing issue --key vendor-license-key.pem \\
        --org "Acme Corp" --plan enterprise --seats 200 --days 365
    python -m app.licensing verify WDN1....                          # sanity-check a blob

The production signing key lives in Secret Manager (warden-license-signing-key) — it
never ships in the repo or image. Only the PUBLIC key is embedded below; a self-hosted
instance verifies with it out of the box (override: WARDEN_LICENSE_PUBKEY).

Customer side: set WARDEN_LICENSE to the blob itself or a path to a file containing it.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import date, datetime, timedelta, timezone
from .config import _env

# TachTech's vendor license public key (Ed25519). The matching private key is held by
# the vendor only. Replaceable for testing/forks via WARDEN_LICENSE_PUBKEY.
VENDOR_PUBKEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAtVA/cNp4QTKPiU70WZcopZzwOSNe1z47GouPSGT2s3I=
-----END PUBLIC KEY-----
"""

_PREFIX = "WDN1"
PLAN_RANK = {"free": 0, "team": 1, "enterprise": 2}
# Short default term under the renewal model: the signed blob lives ~6 weeks, the
# instance renews against the vendor before it lapses. Bounds revocation blast radius.
DEFAULT_TERM_DAYS = 45


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class LicenseError(Exception):
    """Malformed, mis-signed, wrong-plan, or expired license."""


def issue(private_key_pem: bytes, org: str, plan: str, seats: int, expires: str,
          lic_id: str | None = None) -> str:
    """Sign and encode a license blob (vendor side). Pass lic_id to reuse an existing id
    (renewal re-signs the same license with a new expiry); omit to mint a new one."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    if plan not in PLAN_RANK or plan == "free":
        raise LicenseError(f"plan must be team or enterprise, not '{plan}'")
    payload = json.dumps({
        "v": 1, "id": lic_id or f"lic_{secrets.token_hex(4)}", "org": org.strip(),
        "plan": plan, "seats": int(seats),
        "issued": date.today().isoformat(), "expires": expires,
    }, separators=(",", ":"), sort_keys=True).encode()
    key = load_pem_private_key(private_key_pem, password=None)
    return f"{_PREFIX}.{_b64e(payload)}.{_b64e(key.sign(payload))}"


def signing_key() -> bytes | None:
    """The vendor signing key from WARDEN_LICENSE_SIGNING_KEY (PEM), for server-side
    renewal. None when unset — the renewal endpoint then reports itself disabled, keeping
    the key out of the app on deployments that don't need auto-renewal."""
    pem = _env("PALIVANE_LICENSE_SIGNING_KEY", "WARDEN_LICENSE_SIGNING_KEY", "").strip()
    return pem.encode() if pem else None


def verify(blob: str, pubkey_pem: str | None = None, allow_expired: bool = False) -> dict:
    """Decode + verify a license blob; returns the payload. Raises LicenseError.
    allow_expired=True skips the expiry gate (renewal verifies the signature + identity of
    a license whose current term is ending — expiry is expected there)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    parts = (blob or "").strip().split(".")
    if len(parts) != 3 or parts[0] != _PREFIX:
        raise LicenseError("malformed license (expected WDN1.<payload>.<sig>)")
    try:
        payload_raw, sig = _b64d(parts[1]), _b64d(parts[2])
    except Exception:
        raise LicenseError("malformed license encoding")
    pub = load_pem_public_key((pubkey_pem or _pubkey_pem()).encode())
    try:
        pub.verify(sig, payload_raw)
    except InvalidSignature:
        raise LicenseError("invalid license signature")
    try:
        payload = json.loads(payload_raw)
    except ValueError:
        raise LicenseError("bad license payload")
    if payload.get("v") != 1 or payload.get("plan") not in PLAN_RANK:
        raise LicenseError("unsupported license version/plan")
    exp = str(payload.get("expires") or "")
    try:
        if not allow_expired and datetime.strptime(exp, "%Y-%m-%d").date() < datetime.now(timezone.utc).date():
            raise LicenseError(f"license expired {exp}")
    except ValueError:
        raise LicenseError("bad license expiry date")
    return payload


def _pubkey_pem() -> str:
    return _env("PALIVANE_LICENSE_PUBKEY", "WARDEN_LICENSE_PUBKEY", "").strip() or VENDOR_PUBKEY_PEM


def _license_blob() -> str:
    """WARDEN_LICENSE is the blob itself, or a path to a file containing it."""
    raw = _env("PALIVANE_LICENSE", "WARDEN_LICENSE", "").strip()
    if raw and not raw.startswith(_PREFIX) and os.path.exists(raw):
        try:
            raw = open(raw).read().strip()
        except OSError:
            return ""
    return raw


# Verified once per process (license and env don't change while running); a failed
# verification is remembered too, so a bad license logs once instead of per-request.
_cached: dict | None = None
_checked = False


def current() -> dict | None:
    """The instance's active license payload, or None. Invalid/expired = None (logged)."""
    global _cached, _checked
    if _checked:
        return _cached
    _checked = True
    blob = _license_blob()
    if not blob:
        return None
    try:
        _cached = verify(blob)
    except LicenseError as exc:
        import logging
        logging.getLogger("uvicorn.error").warning("WARDEN_LICENSE ignored: %s", exc)
        _cached = None
    return _cached


def licensed_plan() -> str:
    """The instance-wide plan floor granted by the license ('free' when unlicensed)."""
    lic = current()
    return lic["plan"] if lic else "free"


def licensed_seats() -> int:
    lic = current()
    return int(lic.get("seats") or 0) if lic else 0


# --- vendor CLI ---------------------------------------------------------------------------

def _cli(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="app.licensing", description="Palivane vendor license tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate the vendor Ed25519 signing keypair")
    kg.add_argument("--out", default="vendor-license-key.pem", help="private key file (keep secret)")

    iss = sub.add_parser("issue", help="issue a signed license")
    iss.add_argument("--key", required=True, help="vendor private key PEM (file path, or '-' for stdin)")
    iss.add_argument("--org", required=True)
    iss.add_argument("--plan", choices=["team", "enterprise"], required=True)
    iss.add_argument("--seats", type=int, default=0, help="licensed users (0 = plan default)")
    ex = iss.add_mutually_exclusive_group()
    ex.add_argument("--days", type=int, default=365)
    ex.add_argument("--expires", help="YYYY-MM-DD")

    ver = sub.add_parser("verify", help="verify a license blob and print its payload")
    ver.add_argument("blob")
    ver.add_argument("--pubkey", help="public key PEM file (default: embedded vendor key)")

    args = p.parse_args(argv)
    if args.cmd == "keygen":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(args.out, "wb") as f:
            f.write(pem)
        os.chmod(args.out, 0o600)
        pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        print(f"private key written to {args.out} — keep it secret (Secret Manager / offline)")
        print("public key (embed as VENDOR_PUBKEY_PEM / WARDEN_LICENSE_PUBKEY):")
        print(pub.decode(), end="")
    elif args.cmd == "issue":
        import sys as _sys
        pem = _sys.stdin.buffer.read() if args.key == "-" else open(args.key, "rb").read()
        expires = args.expires or (date.today() + timedelta(days=args.days)).isoformat()
        print(issue(pem, args.org, args.plan, args.seats, expires))
    elif args.cmd == "verify":
        pub = open(args.pubkey).read() if args.pubkey else None
        payload = verify(args.blob, pub)
        print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
