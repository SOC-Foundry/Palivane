"""Per-tenant SAML SSO: config API, SP-initiated login redirect, ACS provisioning,
SP metadata, and the unified /sso dispatcher. The xmlsec boundary is mocked."""

from __future__ import annotations

import base64

import app.saml as saml_mod

CERT = "MIIC-fake-cert-body-for-storage-only"
IDP_REDIRECT = "https://idp.example/sso?SAMLRequest=abc"


def _configure(client, **over):
    body = {"idp_entity_id": "https://idp.example/entity",
            "idp_sso_url": "https://idp.example/sso",
            "idp_x509_cert": CERT, "enabled": True}
    body.update(over)
    return client.put("/api/saml", json=body)


def _response(in_response_to: str = "") -> str:
    """A posted SAMLResponse. Only its InResponseTo is read ahead of the (mocked) SDK."""
    attr = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    xml = f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"{attr}/>'
    return base64.b64encode(xml.encode()).decode()


def _start(raw_client, monkeypatch, request_id="_req_1"):
    """SP-initiated login from this browser; returns the response the IdP would post back."""
    monkeypatch.setattr(saml_mod, "login_request", lambda *a, **k: (IDP_REDIRECT, request_id))
    r = raw_client.get("/api/auth/saml/acme/login", follow_redirects=False)
    assert r.status_code == 302
    return _response(request_id)


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
    monkeypatch.setattr(saml_mod, "login_request", lambda *a, **k: (IDP_REDIRECT, "_req_1"))
    r = raw_client.get("/api/auth/saml/acme/login", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("https://idp.example/sso?SAMLRequest=")
    # The request id rides in a cookie scoped to this org's SAML routes, unreadable by script.
    cookie = r.headers["set-cookie"]
    assert "palivane_saml_state=" in cookie and "HttpOnly" in cookie
    assert "Path=/api/auth/saml/acme" in cookie


def test_login_404_when_not_configured(raw_client):
    assert raw_client.get("/api/auth/saml/acme/login", follow_redirects=False).status_code == 404


def test_acs_provisions_user_and_issues_session(client, raw_client, monkeypatch):
    _configure(client, auto_provision=True)   # this test exercises provisioning explicitly
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "sso-saml@acme.com",
                                                                  "nameid": "x", "attributes": {}})
    resp = _start(raw_client, monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": resp, "RelayState": "x"},
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
    def post():
        # A fresh sign-in each time, so only the assertion id repeats.
        resp = _start(raw_client, monkeypatch)
        return raw_client.post("/api/auth/saml/acme/acs",
                               data={"SAMLResponse": resp}, follow_redirects=False)
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
    resp = _start(raw_client, monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs",
                        data={"SAMLResponse": resp, "RelayState": rt}, follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code == 303 and "/extension-connect" in loc and "#sso_token=" in loc


def test_acs_rejects_open_redirect_relaystate(client, raw_client, monkeypatch):
    # A malicious RelayState must not steer the token-bearing redirect off-origin.
    _configure(client, auto_provision=True)
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "sso-saml@acme.com",
                                                                  "nameid": "x", "attributes": {}})
    resp = _start(raw_client, monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs",
                        data={"SAMLResponse": resp, "RelayState": "https://evil.example.com/x"},
                        follow_redirects=False)
    loc = r.headers["location"]
    assert "evil.example.com" not in loc and "#sso_token=" in loc


def test_acs_rejects_invalid_response(client, raw_client, monkeypatch):
    _configure(client)
    def _boom(*a, **k):
        raise saml_mod.SAMLError("signature invalid")
    monkeypatch.setattr(saml_mod, "process_acs", _boom)
    resp = _start(raw_client, monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": resp}, follow_redirects=False)
    assert r.status_code == 401


def test_acs_enforces_allowed_domain(client, raw_client, monkeypatch):
    _configure(client, allowed_domain="acme.com")
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {"email": "user@evil.com",
                                                                  "nameid": "", "attributes": {}})
    resp = _start(raw_client, monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": resp}, follow_redirects=False)
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

# --- browser binding: the response must answer the AuthnRequest THIS browser started ------
# Without it, an attacker posts a validly signed response for their own IdP account from any
# page and the victim is signed into the attacker's session (login CSRF).


def _no_sdk(monkeypatch):
    """process_acs that fails the test if reached: these responses must be refused first."""
    def _reached(*a, **k):
        raise AssertionError("an unbound response reached SAML validation")
    monkeypatch.setattr(saml_mod, "process_acs", _reached)


def test_acs_rejects_sp_initiated_response_from_another_browser(client, raw_client, monkeypatch):
    _configure(client, auto_provision=True)
    _no_sdk(monkeypatch)
    # The attacker's own sign-in produced this response; the victim's browser never started one.
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": _response("_attacker_req")},
                        follow_redirects=False)
    assert r.status_code == 400 and "not started from this browser" in r.json()["detail"]


def test_acs_rejects_response_to_a_different_request(client, raw_client, monkeypatch):
    # The victim did start a sign-in (say the attacker navigated them to /login first), but the
    # posted response answers the attacker's request, not theirs.
    _configure(client, auto_provision=True)
    _start(raw_client, monkeypatch, request_id="_victim_req")
    _no_sdk(monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": _response("_attacker_req")},
                        follow_redirects=False)
    assert r.status_code == 400


def test_acs_rejects_unsolicited_response_while_a_request_is_pending(client, raw_client, monkeypatch):
    # The SDK skips its InResponseTo check when the response has none, so a pending request
    # must not let an unsolicited (attacker-fetched) response through.
    _configure(client, auto_provision=True)
    _start(raw_client, monkeypatch)
    _no_sdk(monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": _response()},
                        follow_redirects=False)
    assert r.status_code == 400


def test_acs_bounces_idp_initiated_login_through_sp_initiated(client, raw_client, monkeypatch):
    # An IdP tile posts an unsolicited response with nothing started here. It is not trusted,
    # but tiles keep working: the browser is sent round an SP-initiated login instead.
    _configure(client, auto_provision=True)
    _no_sdk(monkeypatch)
    rt = "/extension-connect?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcb&state=s"
    r = raw_client.post("/api/auth/saml/acme/acs",
                        data={"SAMLResponse": _response(), "RelayState": rt},
                        follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code == 303 and "/api/auth/saml/acme/login?return_to=" in loc
    assert "#sso_token=" not in loc
    # A RelayState that isn't a safe landing is dropped, not carried into the restart.
    r = raw_client.post("/api/auth/saml/acme/acs",
                        data={"SAMLResponse": _response(), "RelayState": "https://evil.example/x"},
                        follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("/api/auth/saml/acme/login")


def test_acs_hands_the_request_id_to_the_sdk_and_spends_it(client, raw_client, monkeypatch):
    _configure(client, auto_provision=True)
    resp = _start(raw_client, monkeypatch, request_id="_req_42")
    seen = {}

    def _ok(*a, **k):
        seen.update(k)
        return {"email": "sso-saml@acme.com", "nameid": "x", "attributes": {}}
    monkeypatch.setattr(saml_mod, "process_acs", _ok)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": resp},
                        follow_redirects=False)
    assert r.status_code == 303 and seen.get("request_id") == "_req_42"
    # The state cookie is cleared on success, so the same response can't be posted again
    # from this browser on the strength of the old request.
    assert "palivane_saml_state" not in raw_client.cookies
    _no_sdk(monkeypatch)
    again = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": resp},
                            follow_redirects=False)
    assert again.status_code == 400


def test_state_cookie_for_another_org_does_not_count(client, raw_client, monkeypatch):
    from app.auth import SAML_STATE_COOKIE, _saml_state_check
    from app.security import create_token

    class _Req:
        cookies = {SAML_STATE_COOKIE: create_token(
            {"typ": "saml_state", "org": "other", "rid": "_req_1"}, ttl=600)}
    assert _saml_state_check(_Req, "acme") == ""
    assert _saml_state_check(_Req, "other") == "_req_1"


def test_in_response_to_reads_the_envelope_and_never_raises():
    assert saml_mod.in_response_to(_response("_abc")) == "_abc"
    assert saml_mod.in_response_to(_response()) == ""
    for junk in ("", "not-base64!", base64.b64encode(b"<not xml").decode(),
                 base64.b64encode(b'<!DOCTYPE x [<!ENTITY e "y">]><x InResponseTo="&e;"/>').decode()):
        assert saml_mod.in_response_to(junk) == ""
