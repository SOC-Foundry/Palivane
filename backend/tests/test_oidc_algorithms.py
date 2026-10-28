"""IdP tokens are verified with asymmetric algorithms only — real crypto, keys made per test.

The other OIDC tests mock validation out; these exercise authlib itself, so a regression in
the algorithm list (or in authlib) shows up here rather than as a forged login.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import warnings

import pytest

import app.oidc as oidc

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from authlib.jose import JsonWebKey, JsonWebToken

ISS, AUD = "https://idp.example", "palivane-agents"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _claims(**over):
    return {"iss": ISS, "aud": AUD, "sub": "agent-1", "exp": int(time.time()) + 300, **over}


@pytest.fixture
def rsa():
    return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "r1"})


def _keyset(*keys: dict):
    return JsonWebKey.import_key_set({"keys": list(keys)})


def _signed(alg: str, key, kid: str, claims: dict) -> str:
    return JsonWebToken([alg]).encode({"alg": alg, "kid": kid}, claims, key).decode()


def _use(monkeypatch, keyset):
    monkeypatch.setattr(oidc, "_key_set", lambda uri: keyset)


def test_rs256_from_the_idp_verifies(rsa, monkeypatch):
    _use(monkeypatch, _keyset(rsa.as_dict(is_private=False)))
    tok = _signed("RS256", rsa, "r1", _claims())
    assert oidc.validate_agent_jwt(ISS, AUD, tok, jwks_uri="x")["sub"] == "agent-1"


def test_hs256_with_a_symmetric_key_in_the_jwks_is_refused(rsa, monkeypatch):
    # authlib's default decoder would accept this: the JWKS holds an `oct` key and the token
    # is a valid HS256 MAC under it. An IdP's signing keys are asymmetric; a shared secret
    # sitting in a JWKS (by mistake, or planted) must not become a way to mint tokens.
    secret = secrets.token_bytes(32)
    oct_key = {"kty": "oct", "kid": "o1", "k": _b64(secret)}
    _use(monkeypatch, _keyset(rsa.as_dict(is_private=False), oct_key))
    tok = _signed("HS256", secret, "o1", _claims())
    with pytest.raises(oidc.OIDCError):
        oidc.validate_agent_jwt(ISS, AUD, tok, jwks_uri="x")


def test_hs256_signed_with_the_public_key_is_refused(rsa, monkeypatch):
    # The classic confusion forgery: HMAC keyed with the RSA public key's bytes.
    from cryptography.hazmat.primitives import serialization as ser
    _use(monkeypatch, _keyset(rsa.as_dict(is_private=False)))
    pem = rsa.get_public_key().public_bytes(ser.Encoding.PEM,
                                            ser.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(Exception):
        tok = _signed("HS256", pem, "r1", _claims())
        oidc.validate_agent_jwt(ISS, AUD, tok, jwks_uri="x")


def test_unsigned_token_is_refused(rsa, monkeypatch):
    _use(monkeypatch, _keyset(rsa.as_dict(is_private=False)))
    tok = ".".join([_b64(json.dumps({"alg": "none", "kid": "r1"}).encode()),
                    _b64(json.dumps(_claims()).encode()), ""])
    with pytest.raises(oidc.OIDCError):
        oidc.validate_agent_jwt(ISS, AUD, tok, jwks_uri="x")


def test_ema_inspection_only_verifies_asymmetric_tokens(rsa, monkeypatch):
    # inspect_ema_token never raises; an HS256 token must simply come back unverified.
    secret = secrets.token_bytes(32)
    _use(monkeypatch, _keyset(rsa.as_dict(is_private=False),
                              {"kty": "oct", "kid": "o1", "k": _b64(secret)}))
    good = oidc.inspect_ema_token(_signed("RS256", rsa, "r1", _claims(email="a@acme.com")),
                                  trusted_issuer=ISS, jwks_uri="x")
    forged = oidc.inspect_ema_token(_signed("HS256", secret, "o1", _claims(email="a@acme.com")),
                                    trusted_issuer=ISS, jwks_uri="x")
    assert good["verified"] is True
    assert forged["verified"] is False


def test_login_id_token_refuses_hs256(rsa, monkeypatch):
    secret = secrets.token_bytes(32)
    jwks = {"keys": [rsa.as_dict(is_private=False), {"kty": "oct", "kid": "o1", "k": _b64(secret)}]}

    class _Resp:
        def json(self):
            return jwks

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **k):
            return _Resp()
    monkeypatch.setattr(oidc, "safe_client", lambda **k: _Client())
    monkeypatch.setattr(oidc, "_safe", lambda url: url)
    meta = {"jwks_uri": "https://idp.example/jwks"}
    claims = _claims(aud="cid", email="u@acme.com", nonce="n1")
    ok = oidc.validate_id_token(meta, ISS, "cid", _signed("RS256", rsa, "r1", claims), "n1")
    assert ok["email"] == "u@acme.com"
    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(meta, ISS, "cid", _signed("HS256", secret, "o1", claims), "n1")
