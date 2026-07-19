"""Vendor-signed licenses: issue/verify roundtrip, tamper/expiry rejection, plan lift."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

from app import licensing
from app.metering import effective_quota
from app.models import Tenant
from app.plans import has_feature, plan_of


@pytest.fixture
def keypair():
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def _fresh(monkeypatch, blob="", pubkey=""):
    """Point the module at a test license and reset its process-wide cache."""
    monkeypatch.setenv("WARDEN_LICENSE", blob)
    if pubkey:
        monkeypatch.setenv("WARDEN_LICENSE_PUBKEY", pubkey)
    monkeypatch.setattr(licensing, "_cached", None)
    monkeypatch.setattr(licensing, "_checked", False)


def test_issue_verify_roundtrip(keypair):
    priv, pub = keypair
    exp = (date.today() + timedelta(days=30)).isoformat()
    blob = licensing.issue(priv, "Acme Corp", "enterprise", 200, exp)
    assert blob.startswith("WDN1.")
    payload = licensing.verify(blob, pub)
    assert payload["org"] == "Acme Corp" and payload["plan"] == "enterprise"
    assert payload["seats"] == 200 and payload["expires"] == exp


def test_tampered_and_expired_rejected(keypair):
    priv, pub = keypair
    good = licensing.issue(priv, "Acme", "team", 50,
                           (date.today() + timedelta(days=5)).isoformat())
    head, payload_b64, sig = good.split(".")
    # Flip the plan inside the payload — the signature must not survive it.
    forged = licensing._b64e(
        licensing._b64d(payload_b64).replace(b'"team"', b'"enterprise"'))
    with pytest.raises(licensing.LicenseError, match="signature"):
        licensing.verify(f"{head}.{forged}.{sig}", pub)
    expired = licensing.issue(priv, "Acme", "team", 50,
                              (date.today() - timedelta(days=1)).isoformat())
    with pytest.raises(licensing.LicenseError, match="expired"):
        licensing.verify(expired, pub)
    with pytest.raises(licensing.LicenseError, match="malformed"):
        licensing.verify("not-a-license", pub)


def test_free_plan_cannot_be_issued(keypair):
    priv, _ = keypair
    with pytest.raises(licensing.LicenseError):
        licensing.issue(priv, "Acme", "free", 5, "2099-01-01")


def test_license_lifts_instance_plan_and_seats(keypair, monkeypatch):
    priv, pub = keypair
    blob = licensing.issue(priv, "Acme", "enterprise", 137,
                           (date.today() + timedelta(days=30)).isoformat())
    _fresh(monkeypatch, blob, pub)
    t = Tenant(slug="selfhosted", plan="free")
    assert plan_of(t) == "enterprise"          # license lifts the free column
    assert has_feature(t, "sso")
    assert effective_quota(t, "users") == 137  # seats become the users quota
    t.quota_users = 10
    assert effective_quota(t, "users") == 10   # operator override still wins


def test_invalid_license_falls_back_to_free(keypair, monkeypatch):
    _, pub = keypair
    _fresh(monkeypatch, "WDN1.garbage.garbage", pub)
    t = Tenant(slug="selfhosted", plan="free")
    assert plan_of(t) == "free"
    assert licensing.current() is None


def test_license_never_downgrades_a_higher_tenant_plan(keypair, monkeypatch):
    priv, pub = keypair
    blob = licensing.issue(priv, "Acme", "team", 50,
                           (date.today() + timedelta(days=30)).isoformat())
    _fresh(monkeypatch, blob, pub)
    assert plan_of(Tenant(slug="x", plan="enterprise")) == "enterprise"


def test_health_reports_license(keypair, monkeypatch, client):
    priv, pub = keypair
    blob = licensing.issue(priv, "Acme", "team", 50,
                           (date.today() + timedelta(days=30)).isoformat())
    _fresh(monkeypatch, blob, pub)
    lic = client.get("/api/health").json()["license"]
    assert lic == {"org": "Acme", "plan": "team", "expires": lic["expires"]}
    _fresh(monkeypatch)   # no license -> null
    assert client.get("/api/health").json()["license"] is None
