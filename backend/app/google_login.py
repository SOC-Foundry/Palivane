"""App-global "Continue with Google" — social sign-in for the hosted console.

Distinct from the per-tenant OIDC/SAML SSO (the Enterprise feature where an org wires
its own IdP): this is ONE Google OAuth client for the whole deployment, aimed at the
self-serve motion. Google's `email_verified` claim substitutes for the signup flow's
mailbox-proof email, so accounts created here skip the verification round-trip. Dark by
default — enabled() is false until GOOGLE_OAUTH_CLIENT_ID + GOOGLE_OAUTH_CLIENT_SECRET
are set, and the sign-in screen hides the button.

Resolution for the verified email, in order:
  1. exactly one active account with that email  -> sign in (several orgs -> use password)
  2. domain claimed + verified by a tenant       -> join it (auto-approve, or join request)
  3. self-serve signup enabled                   -> new org + first admin (trial),
                                                    mirroring /api/auth/signup
  4. otherwise                                   -> no account; ask an admin for an invite
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from . import oidc
from .auth import _naive_utc, _safe_return_to, _slugify, _unique_slug
from .config import settings
from .database import get_db
from .models import Tenant, User
from .security import TokenError, create_token, decode_token, hash_password

router = APIRouter(prefix="/api", tags=["google-login"])

ISSUER = "https://accounts.google.com"


def enabled() -> bool:
    return bool(settings.google_oauth_client_id and settings.google_oauth_client_secret)


def _origin(request: Request) -> str:
    # The configured public origin beats the client Host header — a spoofed Host must
    # never decide where a session token gets redirected (same rule as tenant SSO).
    return settings.public_base_url or str(request.base_url).rstrip("/")


def _redirect_uri(request: Request) -> str:
    # Must byte-match the URI registered on the Google OAuth client, so prefer the
    # configured public origin over whatever Host the proxy handed us.
    return f"{_origin(request)}/api/auth/google/callback"


@router.get("/auth/google/login")
def google_login(request: Request, return_to: str = ""):
    """Begin the flow: bounce the browser to Google's consent screen."""
    if not enabled():
        raise HTTPException(status_code=404, detail="Google sign-in is not configured")
    meta = oidc.discover(ISSUER)
    nonce = secrets.token_urlsafe(16)
    # Signed, self-expiring state — no server-side session store needed (multi-worker safe).
    # return_to carries the connect landing through Google (signed, so it can't be tampered).
    state = create_token({"typ": "google_state", "nonce": nonce,
                          "return_to": _safe_return_to(return_to)}, ttl=600)
    return RedirectResponse(
        oidc.authorize_url(meta, settings.google_oauth_client_id,
                           _redirect_uri(request), state, nonce),
        status_code=307)


@router.get("/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = "",
                    db: Session = Depends(get_db)):
    if not enabled():
        raise HTTPException(status_code=404, detail="Google sign-in is not configured")
    try:
        payload = decode_token(state)
    except TokenError:
        raise HTTPException(status_code=400, detail="invalid or expired sign-in state")
    if payload.get("typ") != "google_state":
        raise HTTPException(status_code=400, detail="sign-in state mismatch")

    try:
        meta = oidc.discover(ISSUER)
        tokens = oidc.exchange_code(meta, settings.google_oauth_client_id,
                                    settings.google_oauth_client_secret, code,
                                    _redirect_uri(request))
        claims = oidc.validate_id_token(meta, ISSUER, settings.google_oauth_client_id,
                                        tokens.get("id_token", ""), payload.get("nonce", ""))
    except oidc.OIDCError as e:
        raise HTTPException(status_code=401, detail=str(e))

    email = (claims.get("email") or "").lower().strip()
    # Google marks unverified addresses (e.g. some Workspace aliases) — without this,
    # anyone could mint a Google account claiming a victim's email and walk in.
    if not email or claims.get("email_verified") is not True:
        raise HTTPException(status_code=401, detail="Google account email is not verified")

    origin = _origin(request)
    return_to = _safe_return_to(payload.get("return_to", ""))

    # 1. Existing account(s). One match signs in; the same email in several orgs is
    # ambiguous with no org context, so those keep using password/SSO.
    users = db.query(User).filter(User.email == email, User.active.is_(True)).all()
    if len(users) == 1:
        return _signin(db, users[0], origin, return_to)
    if len(users) > 1:
        raise HTTPException(status_code=409,
                            detail="this email belongs to several organizations; "
                                   "sign in with your password instead")

    # 2. Claimed + verified domain -> this signup belongs to that org. The join flow's
    # emailed confirm link exists to prove mailbox ownership; Google already proved it.
    from . import domains as domains_mod
    from .models import JoinRequest
    claim = domains_mod.match_verified(db, email)
    if claim is not None:
        tenant = db.get(Tenant, claim.tenant_id)
        if claim.auto_approve:
            user = User(tenant_id=tenant.id, email=email,
                        password_hash=hash_password(secrets.token_urlsafe(32)),
                        role="analyst", email_verified=True)
            db.add(user)
            db.commit()
            db.refresh(user)
            return _signin(db, user, origin, return_to)
        req = (db.query(JoinRequest)
               .filter(JoinRequest.tenant_id == tenant.id, JoinRequest.email == email)
               .first())
        if req is None or req.status != "pending":
            if req is None:
                req = JoinRequest(tenant_id=tenant.id, email=email,
                                  password_hash=hash_password(secrets.token_urlsafe(32)))
                db.add(req)
            req.status = "pending"
            req.email_verified = True
            db.commit()
        return RedirectResponse(f"{origin}/#join=verified", status_code=303)

    # 3. Fresh self-serve signup: a new org on the trial clock, this user its admin —
    # the same shape /api/auth/signup produces.
    if not settings.allow_signup:
        raise HTTPException(status_code=403,
                            detail="no account for this email. Ask your admin for an invite")
    local, _, dom = email.partition("@")
    org_name = local if dom in domains_mod.FREE_MAIL else dom
    from datetime import timedelta
    trial_days = settings.trial_days
    tenant = Tenant(
        slug=_unique_slug(db, _slugify(org_name)), name=org_name,
        plan="trial" if trial_days > 0 else "free",
        trial_ends_at=(_naive_utc() + timedelta(days=trial_days)) if trial_days > 0 else None)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    user = User(tenant_id=tenant.id, email=email,
                password_hash=hash_password(secrets.token_urlsafe(32)), role="admin",
                email_verified=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return _signin(db, user, origin, return_to)


def _signin(db: Session, user: User, origin: str, return_to: str = "") -> RedirectResponse:
    from .lifecycle import ensure_active
    ensure_active(db, user.tenant_id)
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version})
    # Fragment, not query: the token stays out of server/proxy logs (same as tenant SSO). When a
    # connect flow asked for it, land on /extension-connect so the token handback completes.
    return RedirectResponse(f"{origin}{_safe_return_to(return_to) or '/'}#sso_token={token}",
                            status_code=303)
