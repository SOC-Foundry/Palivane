"""Per-tenant SAML SSO: config API, SP-initiated login redirect, ACS provisioning,
SP metadata, and the unified /sso dispatcher. The xmlsec boundary is mocked."""

from __future__ import annotations

import app.saml as saml_mod

CERT = "MIIC-fake-cert-body-for-storage-only"


def _configure(client, **over):
    body = {"idp_entity_id": "https://idp.example/entity",
            "idp_sso_url": "https://idp.example/sso",
            "idp_x509_cert": CERT, "enabled": True}
    body.update(over)
    return client.put("/api/saml", json=body)


def test_saml_config_crud(client):
    r = _configure(client)
    assert r.status_code == 200
    b = r.json()
    assert b["enabled"] and b["cert_set"] and b["idp_sso_url"] == "https://idp.example/sso"
    got = client.get("/api/saml").json()
    assert got["configured"] and got["idp_entity_id"] == "https://idp.example/entity"
    assert client.delete("/api/saml").json()["configured"] is False


def test_saml_admin_only(raw_client):
    assert raw_client.get("/api/saml").status_code == 401
    assert raw_client.put("/api/saml", json={"idp_entity_id": "x"}).status_code == 401


def test_login_redirects_to_idp(client, raw_client, monkeypatch):
    _configure(client)
    monkeypatch.setattr(saml_mod, "login_url", lambda *a, **k: "https://idp.example/sso?SAMLRequest=abc")
    r = raw_client.get("/api/auth/saml/acme/login", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("https://idp.example/sso?SAMLRequest=")


def test_login_404_when_not_configured(raw_client):
    assert raw_client.get("/api/auth/saml/acme/login", follow_redirects=False).status_code == 404


def test_acs_provisions_user_and_issues_session(client, raw_client, monkeypatch):
    _configure(client, auto_provision=True)   # this test exercises provisioning explicitly
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "sso-saml@acme.com",
                                                                  "nameid": "x", "attributes": {}})
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": "b64", "RelayState": "x"},
                        follow_redirects=False)
    assert r.status_code == 303 and "#sso_token=" in r.headers["location"]
    token = r.headers["location"].split("#sso_token=")[1]
    me = raw_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["user"]["email"] == "sso-saml@acme.com"
    assert me.json()["user"]["role"] == "analyst"


def test_acs_rejects_invalid_response(client, raw_client, monkeypatch):
    _configure(client)
    def _boom(*a, **k):
        raise saml_mod.SAMLError("signature invalid")
    monkeypatch.setattr(saml_mod, "process_acs", _boom)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": "b64"}, follow_redirects=False)
    assert r.status_code == 401


def test_acs_enforces_allowed_domain(client, raw_client, monkeypatch):
    _configure(client, allowed_domain="acme.com")
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "user@evil.com",
                                                                  "nameid": "", "attributes": {}})
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": "b64"}, follow_redirects=False)
    assert r.status_code == 403


def test_sp_metadata_is_served(client, raw_client):
    _configure(client)
    # Use a real-looking Host so the SAML lib's URL validation accepts the ACS URL.
    r = raw_client.get("/api/auth/saml/acme/metadata", headers={"host": "warden.example.com"})
    assert r.status_code == 200 and "EntityDescriptor" in r.text
    assert "/api/auth/saml/acme/acs" in r.text   # our ACS URL is advertised


def test_unified_sso_dispatch_prefers_saml_when_only_saml(client, raw_client):
    _configure(client)
    r = raw_client.get("/api/auth/sso/acme/login", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"].endswith("/api/auth/saml/acme/login")