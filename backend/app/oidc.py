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


def _safe(url: str) -> str:
    """SSRF guard for server-side fetches to IdP-controlled URLs (issuer discovery, token,
    JWKS). Rejects private/loopback/metadata targets so a malicious/misconfigured issuer
    can't turn the server into an internal-network proxy."""
    from .netguard import is_safe_url
    if not is_safe_url(url):
        raise OIDCError(f"refusing to fetch a non-public URL: {url}")
    return url


def discover(issuer: str) -> dict:
    """Fetch the IdP's OpenID configuration (authorization/token/jwks endpoints)."""
    url = _safe(issuer.rstrip("/") + "/.well-known/openid-configuration")
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
            r = c.post(_safe(meta["token_endpoint"]), data=data)
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"OIDC token exchange failed: {e}")


# --- Workload / agent identity (client-credentials JWTs) ------------------------------
# Cache discovery + JWKS so per-request agent-token validation is a local crypto check, not
# a network round-trip. Coarse TTL; JWKS rotation is picked up within the window.
import time as _time  # noqa: E402

_JWKS_CACHE: dict = {}   # jwks_uri -> (key_set, expires_at)
_DISC_CACHE: dict = {}   # issuer -> (meta, expires_at)
_TTL = 3600


def _discover_cached(issuer: str) -> dict:
    hit = _DISC_CACHE.get(issuer)
    if hit and hit[1] > _time.time():
        return hit[0]
    meta = discover(issuer)
    _DISC_CACHE[issuer] = (meta, _time.time() + _TTL)
    return meta


def _key_set(jwks_uri: str):
    hit = _JWKS_CACHE.get(jwks_uri)
    if hit and hit[1] > _time.time():
        return hit[0]
    try:
        with httpx.Client(timeout=10) as c:
            jwks = c.get(_safe(jwks_uri), timeout=10).json()
        ks = JsonWebKey.import_key_set(jwks)
    except Exception as e:
        raise OIDCError(f"JWKS fetch failed: {e}")
    _JWKS_CACHE[jwks_uri] = (ks, _time.time() + _TTL)
    return ks


def validate_agent_jwt(issuer: str, audience: str, token: str, jwks_uri: str = "") -> dict:
    """Validate a workload/agent bearer JWT against the issuer's JWKS (signature + iss + exp,
    and aud when configured). No nonce/email — this is a service credential, not a user login.
    Returns the claims (with `sub`/`client_id`/`azp` for mapping to an Agent)."""
    uri = jwks_uri or _discover_cached(issuer).get("jwks_uri", "")
    if not uri:
        raise OIDCError("no JWKS URI for issuer")
    opts = {"iss": {"essential": True, "value": issuer}, "exp": {"essential": True}}
    if audience:
        opts["aud"] = {"essential": True, "value": audience}
    try:
        claims = jwt.decode(token, _key_set(uri), claims_options=opts)
        claims.validate()
    except OIDCError:
        raise
    except Exception as e:
        raise OIDCError(f"agent token validation failed: {e}")
    return dict(claims)


def validate_id_token(meta: dict, issuer: str, client_id: str, id_token: str,
                      nonce: str) -> dict:
    """Validate the ID token's signature (via the IdP JWKS) and claims, and return them.
    Enforces iss, aud (our client_id), exp, and the round-trip nonce."""
    try:
        with httpx.Client(timeout=10) as c:
            jwks = c.get(_safe(meta["jwks_uri"]), timeout=10).json()
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
