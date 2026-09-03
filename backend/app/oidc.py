"""OIDC (OpenID Connect) helpers for per-tenant SSO — the auth-code flow.

Framework-agnostic and mockable: discovery + token exchange over httpx, ID-token
signature/claims validation via authlib's JOSE (JWKS). The FastAPI routes in auth.py
wire these together; tests mock `exchange_code`/`validate_id_token` at this boundary so
no real IdP is needed.
"""
from __future__ import annotations

import warnings

import httpx

from .netguard import safe_client

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
        with safe_client(timeout=10) as c:
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
        with safe_client(timeout=10) as c:
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
_CACHE_MAX = 64          # bound memory: evict oldest when exceeded (dicts keep insertion order)


def _cache_put(cache: dict, key: str, value) -> None:
    cache[key] = value
    while len(cache) > _CACHE_MAX:
        cache.pop(next(iter(cache)))


def _discover_cached(issuer: str) -> dict:
    hit = _DISC_CACHE.get(issuer)
    if hit and hit[1] > _time.time():
        return hit[0]
    meta = discover(issuer)
    _cache_put(_DISC_CACHE, issuer, (meta, _time.time() + _TTL))
    return meta


def _key_set(jwks_uri: str):
    hit = _JWKS_CACHE.get(jwks_uri)
    if hit and hit[1] > _time.time():
        return hit[0]
    try:
        with safe_client(timeout=10) as c:
            jwks = c.get(_safe(jwks_uri), timeout=10).json()
        ks = JsonWebKey.import_key_set(jwks)
    except Exception as e:
        raise OIDCError(f"JWKS fetch failed: {e}")
    _cache_put(_JWKS_CACHE, jwks_uri, (ks, _time.time() + _TTL))
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


# --- MCP Enterprise-Managed Authorization (EMA) — capture-plane token inspection -------
# EMA (MCP 2026-07-28, `io.modelcontextprotocol/enterprise-managed-authorization`, from
# SEP-990) has the client exchange its SSO assertion at the IdP for an ID-JAG — a
# short-lived JWT authorization grant with header `typ: oauth-id-jag+jwt`, one per target
# MCP server — then redeem it (RFC 7523 JWT-bearer) at the server's AS for the actual MCP
# access token. Where those artifacts are inspectable on the capture plane, we can lift an
# IdP-governed actor identity (`sub`/`email`) for session attribution.
#
# HONESTY (normative — see docs/mcp-ema-integration.md "Honest constraints"): the ID-JAG
# format is normative but the final MCP access token is whatever the server's AS issues —
# for third-party SaaS servers it may be opaque, or signed by keys we have no trust in.
# `inspect_ema_token` therefore NEVER claims validation it didn't do: `verified` is True
# only when the token's signature checked out against the JWKS of a *configured, trusted*
# issuer; everything else is best-effort unverified parsing for attribution, and anything
# unparseable degrades to kind="opaque". Enforcement rests on inline placement, not on
# cryptography we may not have.

ID_JAG_TYP = "oauth-id-jag+jwt"


def _jwt_segment(token: str, index: int) -> dict:
    """Decode one compact-JWS segment (0=header, 1=payload) WITHOUT verification.
    {} on any failure — never raises. Claims read this way must not be trusted for
    authentication, only for attribution/audit metadata."""
    import base64
    import json
    try:
        seg = token.split(".")[index]
        seg += "=" * (-len(seg) % 4)
        out = json.loads(base64.urlsafe_b64decode(seg))
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}


def _claim_str(claims: dict, key: str) -> str:
    """A claim as a display string — RFC 8693/8707 allow `aud`/`resource` to be arrays."""
    v = claims.get(key)
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v)
    return str(v) if v not in (None, "") else ""


def inspect_ema_token(token: str, trusted_issuer: str = "", jwks_uri: str = "") -> dict:
    """Best-effort identity/metadata extraction from a Bearer credential seen on captured
    MCP traffic (EMA-minted MCP access token or ID-JAG). Never raises.

    Returns a dict with:
      kind      "id-jag" (header `typ: oauth-id-jag+jwt`) | "jwt" (parseable JWT of any
                other typ, e.g. an `at+jwt` access token) | "opaque" (non-JWT or
                unparseable — common for third-party AS tokens; not an error)
      verified  True ONLY when the signature validated against `trusted_issuer`'s JWKS
                (the token's `iss` must match). False everywhere else — including
                perfectly well-formed JWTs from issuers we have no trust anchor for.
      sub/email/iss/client_id  actor-identity claims (unverified unless `verified`)
      typ/aud/resource/scope   audience & scope metadata for the audit trail

    Opaque tokens yield {"kind": "opaque", "verified": False} — callers must treat that
    as a normal, attributable-as-opaque outcome, never a failure."""
    opaque = {"kind": "opaque", "verified": False}
    try:
        t = (token or "").strip()
        if not (t.startswith("eyJ") and t.count(".") == 2):
            return opaque
        header, claims = _jwt_segment(t, 0), _jwt_segment(t, 1)
        if not claims:
            return opaque
        typ = str(header.get("typ") or "")
        out = {
            "kind": "id-jag" if typ.lower() == ID_JAG_TYP else "jwt",
            "verified": False,
            "typ": typ,
            "iss": _claim_str(claims, "iss"),
            "sub": _claim_str(claims, "sub"),
            "email": _claim_str(claims, "email"),
            "client_id": _claim_str(claims, "client_id") or _claim_str(claims, "azp"),
            "aud": _claim_str(claims, "aud"),
            "resource": _claim_str(claims, "resource"),
            "scope": _claim_str(claims, "scope"),
        }
        # Signature check — only against an issuer the tenant has explicitly configured
        # (their own IdP). No audience option: the token's audience is the MCP server /
        # its AS, not us; audience is recorded above, not enforced here.
        if trusted_issuer and out["iss"].rstrip("/") == trusted_issuer.rstrip("/"):
            try:
                uri = jwks_uri or _discover_cached(trusted_issuer).get("jwks_uri", "")
                if uri:
                    verified = jwt.decode(t, _key_set(uri), claims_options={
                        "iss": {"essential": True, "value": out["iss"]},
                        "exp": {"essential": True},
                    })
                    verified.validate()
                    out["verified"] = True
                    out["sub"] = _claim_str(dict(verified), "sub")
                    out["email"] = _claim_str(dict(verified), "email")
            except Exception:
                pass  # stays verified=False; unverified claims still attribute
        return out
    except Exception:
        return opaque


def validate_id_token(meta: dict, issuer: str, client_id: str, id_token: str,
                      nonce: str) -> dict:
    """Validate the ID token's signature (via the IdP JWKS) and claims, and return them.
    Enforces iss, aud (our client_id), exp, and the round-trip nonce."""
    try:
        with safe_client(timeout=10) as c:
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
    # If the IdP asserts the email is unverified, don't map it onto an existing account — an
    # unverified/aliased address could otherwise be claimed as someone else's in the tenant.
    # Enforced only when the claim is present (many IdPs omit it), mirroring Google login.
    if claims.get("email_verified") is False:
        raise OIDCError("ID token email is not verified by the identity provider")
    return dict(claims)
