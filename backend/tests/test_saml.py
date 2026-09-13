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


def test_acs_rejects_replayed_assertion(client, raw_client, monkeypatch):
    # An assertion is single-use: the same assertion id, posted twice, authenticates once and
    # is rejected on replay (the SDK verifies signature/conditions but not one-time use).
    _configure(client, auto_provision=True)
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {
        "email": "sso-saml@acme.com", "nameid": "x", "attributes": {},
        "assertion_id": "_assert_replay_1", "not_on_or_after": 0})
    post = lambda: raw_client.post("/api/auth/saml/acme/acs",
                                   data={"SAMLResponse": "b64"}, follow_redirects=False)
    first = post()
    assert first.status_code == 303 and "#sso_token=" in first.headers["location"]
    second = post()
    assert second.status_code == 401 and "replay" in second.json()["detail"].lower()


def test_safe_return_to_validation():
    from app.auth import _safe_return_to
    # Accept the connect landing (redirect_uri arrives URL-encoded, so no literal scheme).
    ok = "/extension-connect?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcb&state=s"
    assert _safe_return_to(ok) == ok
    # Reject anything that could redirect the session token off-origin.
    for bad in ("https://evil.example.com/x", "//evil.example.com", "/console",
                "/extension-connect://evil", "/extension-connect#@evil", "/extension-connect\\x",
                "", "  "):
        assert _safe_return_to(bad) == ""


def test_acs_return_to_lands_on_extension_connect(client, raw_client, monkeypatch):
    # A connect-initiated SSO comes back with RelayState = the /extension-connect landing, so
    # the token handback to the extension/CLI can complete instead of dead-ending on the console.
    _configure(client, auto_provision=True)
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "sso-saml@acme.com",
                                                                  "nameid": "x", "attributes": {}})
    rt = "/extension-connect?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcb&state=s"
    r = raw_client.post("/api/auth/saml/acme/acs",
                        data={"SAMLResponse": "b64", "RelayState": rt}, follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code == 303 and "/extension-connect" in loc and "#sso_token=" in loc


def test_acs_rejects_open_redirect_relaystate(client, raw_client, monkeypatch):
    # A malicious RelayState must not steer the token-bearing redirect off-origin.
    _configure(client, auto_provision=True)
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "sso-saml@acme.com",
                                                                  "nameid": "x", "attributes": {}})
    r = raw_client.post("/api/auth/saml/acme/acs",
                        data={"SAMLResponse": "b64", "RelayState": "https://evil.example.com/x"},
                        follow_redirects=False)
    loc = r.headers["location"]
    assert "evil.example.com" not in loc and "#sso_token=" in loc


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
    r = raw_client.get("/api/auth/saml/acme/metadata", headers={"host": "palivane.example.com"})
    assert r.status_code == 200 and "EntityDescriptor" in r.text
    assert "/api/auth/saml/acme/acs" in r.text   # our ACS URL is advertised


def test_unified_sso_dispatch_prefers_saml_when_only_saml(client, raw_client):
    _configure(client)
    r = raw_client.get("/api/auth/sso/acme/login", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"].endswith("/api/auth/saml/acme/login")