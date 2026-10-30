"""Low-severity fixes from the deep QA: auth and accounts, OAuth and MCP, SSO."""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import AuditLog, Tenant, User

REDIRECT = "https://claude.ai/cb"


# --- auth and accounts ---------------------------------------------------------------------

def test_negative_trial_days_is_refused():
    from app.users import apply_plan
    t = Tenant(name="t", slug="t", plan="free")
    with pytest.raises(ValueError):
        apply_plan(t, "trial", -5)
    apply_plan(t, "trial", 0)
    assert t.plan == "trial" and t.trial_ends_at is None        # 0 stays open-ended on purpose


@pytest.mark.parametrize("n", [0, -1])
def test_enrollment_max_uses_must_be_positive(client, n):
    assert client.post("/api/enroll/tokens", json={"label": "x", "max_uses": n}).status_code == 422
    assert client.post("/api/enroll/tokens", json={"label": "x", "max_uses": 1}).status_code == 200


def test_rotating_a_disabled_agent_keeps_it_disabled(client):
    a = client.post("/api/agents", json={"name": "ci-bot"}).json()
    assert client.delete(f"/api/agents/{a['id']}").status_code == 200
    r = client.post(f"/api/agents/{a['id']}/rotate").json()
    assert r["active"] is False and r["token"]
    r = client.patch(f"/api/agents/{a['id']}", json={"active": True})
    assert r.status_code == 200 and r.json()["active"] is True


def test_an_inactive_admin_can_be_demoted(client, db_factory):
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    gone = User(tenant_id=t.id, email="old-admin@acme.com", role="admin", active=False,
                password_hash="x")
    db.add(gone); db.commit(); gid = gone.id; db.close()
    r = client.patch(f"/api/users/{gid}", json={"role": "analyst"})
    assert r.status_code == 200 and r.json()["role"] == "analyst"


def test_api_key_actions_say_so_in_the_audit_log(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "ci-triage",
                                            "scope": "console_write"}).json()["token"]
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    from app.models import Finding
    f = Finding(tenant_id=t.id, fingerprint="k", subject="k")
    db.add(f); db.commit(); fid = f.id; db.close()
    r = raw_client.patch(f"/api/findings/{fid}", json={"status": "triaged"},
                         headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    client.patch(f"/api/findings/{fid}", json={"status": "open"})     # by the session
    db = db_factory()
    try:
        rows = (db.query(AuditLog).filter(AuditLog.target == str(fid))
                  .order_by(AuditLog.id).all())
        by_key, by_session = rows[0], rows[-1]
        assert "API key 'ci-triage'" in (by_key.detail or {}).get("via", "")
        assert "via" not in (by_session.detail or {})
    finally:
        db.close()


# --- OAuth and MCP -------------------------------------------------------------------------

def test_dynamic_registration_issues_no_secret(raw_client):
    r = raw_client.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "t"})
    assert r.status_code in (200, 201)
    body = r.json()
    assert not body.get("client_secret") and body["token_endpoint_auth_method"] == "none"


def test_a_wrong_pkce_verifier_burns_the_code(client, raw_client):
    cid = raw_client.post("/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    code = client.post("/api/oauth/consent", json={
        "client_id": cid, "redirect_uri": REDIRECT, "code_challenge": challenge,
    }).json()["redirect_to"].split("code=")[1].split("&")[0]
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": cid}
    assert raw_client.post("/token", data={**form, "code_verifier": "w" * 64}).status_code >= 400
    # The right verifier no longer helps: the code had its one attempt.
    assert raw_client.post("/token", data={**form, "code_verifier": verifier}).status_code >= 400


def test_stdio_server_hints_read_only_only_when_that_is_the_reason():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[2] / "mcp-server" / "palivane_mcp.py").read_text()
    assert '"read-only" in r.text' in src


# --- SSO -----------------------------------------------------------------------------------

def _claims_check(claims, client_id="ours"):
    """Run validate_id_token's claim checks without a real IdP (the JWT decode is faked)."""
    from app import oidc

    class _C(dict):
        def validate(self):
            pass

    import unittest.mock as m
    with m.patch.object(oidc, "safe_client"), m.patch.object(oidc, "_safe", lambda u: u), \
            m.patch.object(oidc.JsonWebKey, "import_key_set"), \
            m.patch.object(oidc._jwt, "decode", return_value=_C(claims)):
        return oidc.validate_id_token({"jwks_uri": "https://idp.example.com/jwks"},
                                      "https://idp.example.com", client_id, "tok", "")


def test_multi_audience_token_needs_our_azp():
    from app.oidc import OIDCError
    base = {"email": "a@acme.com", "aud": ["ours", "theirs"]}
    with pytest.raises(OIDCError):
        _claims_check({**base, "azp": "theirs"})
    with pytest.raises(OIDCError):
        _claims_check(base)
    assert _claims_check({**base, "azp": "ours"})["email"] == "a@acme.com"
    assert _claims_check({"email": "a@acme.com", "aud": "ours"})["email"] == "a@acme.com"


def _oidc_on(client):
    r = client.put("/api/oidc", json={"issuer": "https://idp.example.com", "client_id": "c",
                                      "client_secret": "s", "enabled": True})
    assert r.status_code == 200, r.text


def test_discovery_failure_is_a_502_not_a_500(client, monkeypatch):
    from app import oidc
    _oidc_on(client)

    def down(issuer):
        raise oidc.OIDCError("OIDC discovery failed for x: unreachable")

    monkeypatch.setattr(oidc, "discover", down)
    r = TestClient(app).get("/api/auth/oidc/acme/login", follow_redirects=False)
    assert r.status_code == 502 and "issuer URL" in r.json()["detail"]


@pytest.mark.parametrize("issuer", ["http://idp.example.com", "https://127.0.0.1",
                                    "https://169.254.169.254", "not a url"])
def test_idp_urls_are_checked_when_saved(client, issuer):
    r = client.put("/api/oidc", json={"issuer": issuer, "client_id": "c", "client_secret": "s"})
    assert r.status_code == 400


def test_saml_sso_url_must_be_https(client):
    r = client.put("/api/saml", json={"idp_entity_id": "e", "idp_sso_url": "http://idp.example.com/sso",
                                      "idp_x509_cert": "x"})
    assert r.status_code == 400


def test_mfa_sso_keeps_return_to(db_factory):
    from app.auth import sso_session_redirect
    db = db_factory()
    try:
        u = User(id=999, tenant_id=1, email="m@acme.com", role="analyst", mfa_enabled=True,
                 token_version=0, password_hash="x")
        loc = sso_session_redirect(u, "https://app.example", "/extension-connect?x=1").headers["location"]
        assert "#mfa_challenge=" in loc and "&return_to=%2Fextension-connect%3Fx%3D1" in loc
        loc = sso_session_redirect(u, "https://app.example", "").headers["location"]
        assert "return_to" not in loc
    finally:
        db.close()
