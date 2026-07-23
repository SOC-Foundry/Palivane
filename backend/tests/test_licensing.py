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


# --- registry + short-term renewal (owner license lifecycle) ----------------------------

def _keypair_env(monkeypatch, keypair):
    priv, pub = keypair
    monkeypatch.setenv("WARDEN_LICENSE_SIGNING_KEY", priv.decode())
    monkeypatch.setenv("WARDEN_LICENSE_PUBKEY", pub)
    monkeypatch.setattr(licensing, "_cached", None)
    monkeypatch.setattr(licensing, "_checked", False)
    return priv, pub


def _seed_license(db_factory, lic_id, *, status="active", expires_days=1, contract_days=365):
    from datetime import datetime, timedelta
    from app.models import License
    db = db_factory()
    db.add(License(id=lic_id, org="Acme", plan="enterprise", seats=100, status=status,
                   expires_at=datetime.utcnow() + timedelta(days=expires_days),
                   contract_until=(datetime.utcnow() + timedelta(days=contract_days)
                                   if contract_days else None)))
    db.commit(); db.close()


def test_issue_reuses_id_and_verify_allows_expired(keypair):
    priv, pub = keypair
    blob = licensing.issue(priv, "Acme", "enterprise", 100, "2020-01-01", lic_id="lic_fixed")
    # expired -> normal verify rejects, allow_expired accepts (renewal path)
    import pytest
    with pytest.raises(licensing.LicenseError):
        licensing.verify(blob, pub)
    p = licensing.verify(blob, pub, allow_expired=True)
    assert p["id"] == "lic_fixed" and p["org"] == "Acme"


def test_renew_disabled_without_signing_key(raw_client, monkeypatch):
    monkeypatch.delenv("WARDEN_LICENSE_SIGNING_KEY", raising=False)
    r = raw_client.post("/api/license/renew", json={"license": "WDN1.x.y"})
    assert r.status_code == 503


def test_renew_happy_path_extends_term(raw_client, db_factory, monkeypatch, keypair):
    priv, _ = _keypair_env(monkeypatch, keypair)
    blob = licensing.issue(priv, "Acme", "enterprise", 100, "2020-01-01", lic_id="lic_renew1")
    _seed_license(db_factory, "lic_renew1")
    r = raw_client.post("/api/license/renew", json={"license": blob})
    assert r.status_code == 200, r.text
    body = r.json()
    # a fresh, currently-valid blob comes back (normal verify, no allow_expired)
    p = licensing.verify(body["license"])
    assert p["id"] == "lic_renew1"
    from datetime import date
    assert body["expires"] > date.today().isoformat()


def test_renew_refused_when_revoked(raw_client, db_factory, monkeypatch, keypair):
    priv, _ = _keypair_env(monkeypatch, keypair)
    blob = licensing.issue(priv, "Acme", "enterprise", 100, "2020-01-01", lic_id="lic_rev")
    _seed_license(db_factory, "lic_rev", status="revoked")
    assert raw_client.post("/api/license/renew", json={"license": blob}).status_code == 403


def test_renew_refused_past_contract_end(raw_client, db_factory, monkeypatch, keypair):
    priv, _ = _keypair_env(monkeypatch, keypair)
    blob = licensing.issue(priv, "Acme", "enterprise", 100, "2020-01-01", lic_id="lic_exp")
    _seed_license(db_factory, "lic_exp", contract_days=-1)   # contract already ended
    assert raw_client.post("/api/license/renew", json={"license": blob}).status_code == 403


def test_renew_unknown_license_404(raw_client, monkeypatch, keypair):
    priv, _ = _keypair_env(monkeypatch, keypair)
    blob = licensing.issue(priv, "Ghost", "team", 5, "2020-01-01", lic_id="lic_ghost")
    assert raw_client.post("/api/license/renew", json={"license": blob}).status_code == 404


def test_admin_licenses_requires_metrics_token(client, raw_client, db_factory, monkeypatch):
    from app import main
    _seed_license(db_factory, "lic_view")
    monkeypatch.setattr(main.settings, "metrics_token", "")
    assert raw_client.get("/api/admin/licenses").status_code == 404
    monkeypatch.setattr(main.settings, "metrics_token", "m3trics")
    assert client.get("/api/admin/licenses").status_code == 401   # tenant JWT insufficient
    ok = raw_client.get("/api/admin/licenses", headers={"Authorization": "Bearer m3trics"})
    assert ok.status_code == 200 and any(L["id"] == "lic_view" for L in ok.json()["licenses"])


def test_admin_issue_and_revoke_endpoints(client, raw_client, monkeypatch, keypair):
    from app import main
    priv, pub = keypair
    _keypair_env(monkeypatch, keypair)                    # mounts signing key + pubkey
    monkeypatch.setattr(main.settings, "metrics_token", "op-tok")
    H = {"Authorization": "Bearer op-tok"}
    # gating: tenant JWT and no-token both rejected
    assert client.post("/api/admin/licenses", json={"org": "X", "plan": "team"}).status_code == 401
    assert raw_client.post("/api/admin/licenses", json={"org": "X", "plan": "team"}).status_code == 401
    # issue records + returns a verifiable blob
    r = raw_client.post("/api/admin/licenses",
                        json={"org": "Acme", "plan": "enterprise", "seats": 40}, headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org"] == "Acme" and body["status"] == "active"
    p = licensing.verify(body["license"])
    assert p["id"] == body["id"] and p["plan"] == "enterprise"
    # it shows in the registry, then revoke flips status
    listed = raw_client.get("/api/admin/licenses", headers=H).json()["licenses"]
    assert any(L["id"] == body["id"] for L in listed)
    rev = raw_client.post(f"/api/admin/licenses/{body['id']}/revoke", headers=H)
    assert rev.status_code == 200 and rev.json()["status"] == "revoked"
    assert raw_client.post("/api/admin/licenses/lic_nope/revoke", headers=H).status_code == 404


def test_admin_issue_503_without_signing_key(raw_client, monkeypatch):
    from app import main
    monkeypatch.delenv("WARDEN_LICENSE_SIGNING_KEY", raising=False)
    monkeypatch.setattr(main.settings, "metrics_token", "op-tok")
    r = raw_client.post("/api/admin/licenses", json={"org": "X", "plan": "team"},
                        headers={"Authorization": "Bearer op-tok"})
    assert r.status_code == 503
