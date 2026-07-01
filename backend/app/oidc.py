"""OIDC (OpenID Connect) helpers for per-tenant SSO — the auth-code flow.

Framework-agnostic and mockable: discovery + token exchange over httpx, ID-token
signature/claims validation via authlib's JOSE (JWKS). The FastAPI routes in auth.py
wire these together; tests mock `exchange_code`/`validate_id_token` at this boundary so
no real IdP is needed.
"""
from __future__ import annotations

import warnings

import httpx

with warnings.catch_warnings():   # authlib.jose is "deprecated" but supported pre-2.0
    warnings.simplefilter("ignore")
    from authlib.jose import JsonWebKey, jwt


class OIDCError(Exception):
    """Any failure discovering, exchanging, or validating — surfaced as an auth error."""


def discover(issuer: str) -> dict:
    """Fetch the IdP's OpenID configuration (authorization/token/jwks endpoints)."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=10) as c:
            r = c.get(url)
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"OIDC discovery failed for {issuer}: {e}")


def authorize_url(meta: dict, client_id: str, redirect_uri: str, state: str, nonce: str) -> str:
    from urllib.parse import urlencode
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    return meta["authorization_endpoint"] + "?" + urlencode(params)


def exchange_code(meta: dict, client_id: str, client_secret: str, code: str,
                  redirect_uri: str) -> dict:
    """Swap the auth code for tokens at the IdP's token endpoint. Returns the token set
    (must contain `id_token`)."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        with httpx.Client(timeout=10) as c:
            r = c.post(meta["token_endpoint"], data=data)
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"OIDC token exchange failed: {e}")


def validate_id_token(meta: dict, issuer: str, client_id: str, id_token: str,
                      nonce: str) -> dict:
    """Validate the ID token's signature (via the IdP JWKS) and claims, and return them.
    Enforces iss, aud (our client_id), exp, and the round-trip nonce."""
    try:
        with httpx.Client(timeout=10) as c:
            jwks = c.get(meta["jwks_uri"], timeout=10).json()
        key_set = JsonWebKey.import_key_set(jwks)
        claims = jwt.decode(id_token, key_set, claims_options={
            "iss": {"essential": True, "value": issuer},
            "aud": {"essential": True, "value": client_id},
            "exp": {"essential": True},
        })
        claims.validate()
    except Exception as e:   # authlib raises various; treat all as an auth failure
        raise OIDCError(f"ID token validation failed: {e}")
    if nonce and claims.get("nonce") != nonce:
        raise OIDCError("OIDC nonce mismatch")
    email = claims.get("email")
    if not email:
        raise OIDCError("ID token has no email claim")
    return dict(claims)
