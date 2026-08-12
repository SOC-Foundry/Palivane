"""EMA (MCP enterprise-managed authorization) — capture-plane integration.

Item 1: EMA-minted token / ID-JAG recognition as actor identity on the MCP ingest path,
including the honest opaque-token fallback (docs/mcp-ema-integration.md).
Item 2: ID-JAG issuance-leg detection in the egress-proxy addon (synthetic RFC 8693 /
RFC 7523 fixtures) and its persistence as session events.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import time
from pathlib import Path
from urllib.parse import urlencode

import app.oidc as oidc

_spec = importlib.util.spec_from_file_location(
    "palivane_addon", Path(__file__).resolve().parents[2] / "proxy" / "palivane_addon.py")
addon = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(addon)


def _jwt(claims: dict, typ: str = "", alg: str = "RS256") -> str:
    """An UNSIGNED compact JWS (garbage signature) — exercises the unverified-parse path."""
    header = {"alg": alg}
    if typ:
        header["typ"] = typ

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg(header)}.{seg(claims)}.sig"


# --- Item 1: inspect_ema_token — recognition + opaque fallback -------------------------

def test_id_jag_recognized_unverified():
    tok = _jwt({"iss": "https://acme.okta.com", "sub": "u-123", "email": "dev@acme.com",
                "aud": "https://mcp.asana.com/oauth", "resource": "https://mcp.asana.com",
                "scope": "mcp"}, typ="oauth-id-jag+jwt")
    out = oidc.inspect_ema_token(tok)
    assert out["kind"] == "id-jag"
    assert out["verified"] is False          # no trust anchor -> never claim validation
    assert out["sub"] == "u-123" and out["email"] == "dev@acme.com"
    assert out["aud"] == "https://mcp.asana.com/oauth"
    assert out["resource"] == "https://mcp.asana.com"


def test_plain_jwt_access_token_recognized():
    tok = _jwt({"iss": "https://as.linear.app", "sub": "u-9",
                "aud": ["https://mcp.linear.app", "x"], "scope": "read write"}, typ="at+jwt")
    out = oidc.inspect_ema_token(tok)
    assert out["kind"] == "jwt" and out["typ"] == "at+jwt"
    assert out["aud"] == "https://mcp.linear.app x"   # array audiences join for display
    assert out["verified"] is False


def test_opaque_tokens_degrade_gracefully():
    # Non-JWT (the common third-party-AS case) and JWT-shaped-but-unparseable both come
    # back attributable-as-opaque — never an exception, never a fabricated identity.
    for tok in ("mcp_at_2f9c81b7", "", "eyJhbGciOi.not-base64-json!.sig"):
        out = oidc.inspect_ema_token(tok)
        assert out == {"kind": "opaque", "verified": False}


def test_verified_only_against_configured_issuer(monkeypatch):
    from authlib.jose import JsonWebKey, jwt as jose_jwt
    key = JsonWebKey.import_key({"kty": "oct", "kid": "k1",
                                 "k": base64.urlsafe_b64encode(b"0" * 32).rstrip(b"=").decode()})
    claims = {"iss": "https://idp.test", "sub": "u-1", "email": "dev@acme.com",
              "aud": "https://mcp.acme.dev", "exp": int(time.time()) + 300}
    signed = jose_jwt.encode({"alg": "HS256", "typ": "oauth-id-jag+jwt", "kid": "k1"},
                             claims, key)
    signed = signed.decode() if isinstance(signed, bytes) else signed
    monkeypatch.setattr(oidc, "_discover_cached", lambda iss: {"jwks_uri": "https://idp.test/jwks"})
    monkeypatch.setattr(oidc, "_key_set", lambda uri: key)

    out = oidc.inspect_ema_token(signed, trusted_issuer="https://idp.test")
    assert out["verified"] is True and out["email"] == "dev@acme.com"

    # Same token, no configured trust anchor -> claims extracted, verified stays False.
    out = oidc.inspect_ema_token(signed)
    assert out["verified"] is False and out["email"] == "dev@acme.com"

    # Bad signature against the trusted issuer -> degrade to unverified, never raise.
    tampered = signed.rsplit(".", 1)[0] + ".AAAA"
    out = oidc.inspect_ema_token(tampered, trusted_issuer="https://idp.test")
    assert out["verified"] is False and out["sub"] == "u-1"


# --- Item 1: MCP ingest path attributes the EMA identity --------------------------------

def _key(client):
    return client.post("/api/apikeys", json={"label": "mcp", "actor": "proxy@acme.com"}).json()["token"]


def _post(raw_client, key, **body):
    return raw_client.post("/api/ingest/mcp", json=body, headers={"X-Palivane-Token": key})


def test_ema_token_maps_actor_on_mcp_ingest(client, raw_client):
    key = _key(client)
    tok = _jwt({"iss": "https://acme.okta.com", "sub": "u-7", "email": "mallory@acme.com"},
               typ="oauth-id-jag+jwt")
    r = _post(raw_client, key, method="tools/call", tool="write_file",
              args_text="key=AKIAABCDEFGHIJKLMNOP", authorization=tok)
    assert r.status_code == 200
    finding_id = r.json()["finding_id"]
    findings = client.get("/api/findings").json()["findings"]
    mine = next(f for f in findings if f["id"] == finding_id)
    assert mine["sender"] == "mallory@acme.com"      # IdP-governed identity, not the key's
    # The raw credential must never reach the stored finding (list or detail view).
    detail = client.get(f"/api/findings/{finding_id}").json()
    assert tok not in json.dumps(mine) and tok not in json.dumps(detail)


def test_opaque_authorization_never_breaks_ingest(client, raw_client):
    key = _key(client)
    r = _post(raw_client, key, method="tools/call", tool="list_files",
              args_text="path=./src", authorization="opaque-token-xyz", user="dev@acme.com")
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    # No identity extractable -> attribution falls back to the client-reported user.


def test_ema_sub_used_when_no_email(client, raw_client):
    key = _key(client)
    tok = _jwt({"iss": "https://acme.okta.com", "sub": "u-42"}, typ="oauth-id-jag+jwt")
    r = _post(raw_client, key, method="tools/call", tool="write_file",
              args_text="key=AKIAABCDEFGHIJKLMNOP", authorization=tok)
    finding_id = r.json()["finding_id"]
    findings = client.get("/api/findings").json()["findings"]
    assert next(f for f in findings if f["id"] == finding_id)["sender"] == "u-42"


# --- Item 2: ID-JAG issuance-leg detection (addon) + session-event persistence ---------

def _issuance_body(**over):
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
        "audience": "https://mcp.asana.com/oauth",
        "resource": "https://mcp.asana.com",
        "scope": "mcp",
        "client_id": "claude-code",
        "subject_token": _jwt({"sub": "u-1", "iss": "https://acme.okta.com"}),
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
    }
    form.update(over)
    return urlencode(form).encode()


def test_issuance_leg_detected():
    tx = addon.extract_token_exchange(_issuance_body())
    assert tx["method"] == "auth/id-jag.issuance"
    assert "audience=https://mcp.asana.com/oauth" in tx["args_text"]
    assert "resource=https://mcp.asana.com" in tx["args_text"]
    assert "scope=mcp" in tx["args_text"]
    # Token material never rides into the audit event.
    assert "subject_token" not in tx["args_text"] and "eyJ" not in tx["args_text"]


def test_plain_token_exchange_is_not_id_jag():
    body = _issuance_body(requested_token_type="urn:ietf:params:oauth:token-type:access_token")
    assert addon.extract_token_exchange(body) is None


def test_redemption_leg_detected_via_assertion_typ():
    jag = _jwt({"iss": "https://acme.okta.com", "sub": "u-1", "email": "dev@acme.com",
                "aud": "https://mcp.linear.app/oauth", "resource": "https://mcp.linear.app"},
               typ="oauth-id-jag+jwt")
    body = urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                      "assertion": jag}).encode()
    tx = addon.extract_token_exchange(body)
    assert tx["method"] == "auth/id-jag.redemption"
    assert "audience=https://mcp.linear.app/oauth" in tx["args_text"]
    assert "resource=https://mcp.linear.app" in tx["args_text"]
    assert jag not in tx["args_text"]


def test_ordinary_jwt_bearer_ignored():
    body = urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                      "assertion": _jwt({"iss": "x"}, typ="JWT")}).encode()
    assert addon.extract_token_exchange(body) is None


def test_json_and_jsonrpc_bodies_ignored():
    assert addon.extract_token_exchange(b'{"jsonrpc": "2.0", "method": "tools/call"}') is None
    assert addon.extract_token_exchange(b"") is None
    assert addon.extract_token_exchange(b"a=1&b=2") is None


def test_bearer_token_helper():
    assert addon.bearer_token("Bearer abc.def.ghi") == "abc.def.ghi"
    assert addon.bearer_token("bearer tok") == "tok"
    assert addon.bearer_token("Basic dXNlcjpwdw==") == ""
    assert addon.bearer_token("") == ""


def test_scan_mcp_forwards_authorization(monkeypatch, tmp_path):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path))
    sent = {}

    class _Resp:
        def read(self):
            return b'{"action": "allow"}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        sent["data"] = json.loads(req.data)
        return _Resp()

    monkeypatch.setattr(addon.urllib.request, "urlopen", fake_urlopen)
    addon.scan_mcp({"method": "tools/call", "tool": "x"}, server="mcp.acme.dev",
                   authorization="tok-123", token="ak_test")
    assert sent["data"]["authorization"] == "tok-123"
    # And omitted entirely when the request carried no credential.
    addon.scan_mcp({"method": "initialize"}, server="mcp.acme.dev", token="ak_test")
    assert "authorization" not in sent["data"]


def test_issuance_event_persists_and_skips_server_allowlist(client, raw_client):
    # auth/* events are the audit trail: persisted even though benign, and their server
    # (the IdP token endpoint) is exempt from the MCP server allowlist check.
    client.patch("/api/tenant", json={"mcp_allowed_servers": "mcp.acme.com"})
    key = _key(client)
    r = _post(raw_client, key, method="auth/id-jag.issuance", server="acme.okta.com",
              args_text="audience=https://mcp.asana.com/oauth\nresource=https://mcp.asana.com\nscope=mcp")
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "mcp_untrusted_server" not in {s["category"] for s in body["signals"]}
    assert body["finding_id"] is not None        # persisted despite being benign
    findings = client.get("/api/findings").json()["findings"]
    mine = next(f for f in findings if f["id"] == body["finding_id"])
    assert mine["subject"] == "MCP auth/id-jag.issuance" and mine["surface"] == "mcp"
