"""Authentication dependencies and the /api/auth + /api/users routes.

`get_current_user` turns a Bearer token into the authenticated `User` (loaded fresh
from the DB so deactivation/role changes take effect immediately). `require_admin`
gates user-management routes. Tenant isolation is enforced by callers scoping their
queries to `current_user.tenant_id`.
"""

from __future__ import annotations

import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from . import audit_log, oidc, saml, totp
from .config import settings
from . import crypto
from .crypto import decrypt, encrypt, seal
from .database import get_db
from .models import (
    Agent, AgentRole, ApiKey, AuditLog, DiscoveredUsage, EnrollmentToken, Finding,
    GatewayUsage, LoginAttempt, PolicyOverride, Tenant, TenantOIDC, TenantSAML,
    TenantUpstream, User,
)
from .schemas import (
    AgentCreate, AgentRoleIn, AgentTokenRequest, AgentUpdate, ApiKeyCreate, EnrollmentTokenCreate, EnrollRequest, LoginRequest, MFACode, MFAVerify,
    DPAAccept, ForgotRequest, OIDCConfig, ResetRequest, SAMLConfig, SignupRequest, TenantDelete, TenantUpdate,
    JudgeKeyConfig, UpstreamConfig, UserCreate, UserUpdate,
)
from .upstreams import PROVIDERS, forwards as upstream_forwards
from .security import (
    DUMMY_PASSWORD_HASH,
    TokenError,
    create_token,
    decode_token,
    generate_agent_token,
    generate_api_key,
    generate_enrollment_token,
    hash_password,
    hash_token,
    needs_rehash,
    verify_password,
)


def _naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:48] or "org"


def _unique_slug(db: Session, base: str) -> str:
    slug, n = base, 2
    while db.query(Tenant).filter(Tenant.slug == slug).first():
        slug, n = f"{base}-{n}", n + 1
    return slug


def _session_payload(user: User, tenant: Tenant) -> dict:
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version})
    return {"access_token": token, "token_type": "bearer",
            "user": user.to_dict(), "tenant": tenant.to_dict()}

router = APIRouter(prefix="/api", tags=["auth"])


def get_current_user(
    request: Request,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> User:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = decode_token(token)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc),
                            headers={"WWW-Authenticate": "Bearer"})
    # Public-demo sessions (app/demo.py) are read-only: browsing is fine, anything that
    # mutates is not — a shared demo org must look the same for the next visitor.
    if payload.get("demo") and request.method not in ("GET", "HEAD", "OPTIONS"):
        raise HTTPException(status_code=403,
                            detail="the demo is read-only — sign up to work with your own data")
    # Hand the claim to the handlers too, so /auth/me can tell the console it is looking at
    # sample data. The browser used to keep its own copy of this and the two could disagree.
    request.state.demo_session = bool(payload.get("demo"))
    # Only a *session* token authenticates. Special-purpose tokens carry a `typ`
    # (MFA challenge, OIDC state) — they must NOT be accepted here, or a caller who
    # only passed the first factor could use the MFA challenge as a full session.
    if payload.get("typ"):
        raise HTTPException(status_code=401, detail="not a session token",
                            headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    if int(payload.get("tv", 0)) != user.token_version:
        raise HTTPException(status_code=401, detail="session revoked, please sign in again")
    from .lifecycle import ensure_active
    ensure_active(db, user.tenant_id)
    # Scope the DB session to this tenant so RLS enforces isolation on everything the
    # request touches after auth (defense-in-depth with the app-level tenant_id filters).
    from .database import bind_tenant
    bind_tenant(db, user.tenant_id)
    return user


def require_admin(current: User = Depends(get_current_user)) -> User:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return current


@router.post("/auth/signup")
def signup(body: SignupRequest, request: Request, db: Session = Depends(get_db)):
    """Self-serve onboarding: create a new org (tenant) + its first admin, and log in.

    The first user of a new tenant is its admin; they then invite analysts via /api/users
    and configure the capture planes. Disabled when PALIVANE_ALLOW_SIGNUP=false.

    Domain capture: when the email's domain is claimed + verified by an existing tenant,
    no new org is created — the signup becomes a join request for that tenant (approved
    by its admin, or immediately when the domain has auto_approve)."""
    if not settings.allow_signup:
        raise HTTPException(status_code=403, detail="self-serve signup is disabled")

    from . import domains as domains_mod
    from .models import JoinRequest
    email = body.email.lower().strip()
    # Public endpoint — throttle org-creation abuse per IP (reuses the login limiter, so a
    # single source can't mass-create orgs or, once email is on, spam verification mails).
    ip = _client_ip(request)
    if _throttled(db, email, ip):
        raise HTTPException(status_code=429,
                            detail="too many signups from here, try again later")
    db.add(LoginAttempt(email=email, ip=ip))
    db.commit()
    claim = domains_mod.match_verified(db, email)
    if claim is not None:
        tenant = db.get(Tenant, claim.tenant_id)
        if db.query(User).filter(User.tenant_id == claim.tenant_id,
                                 User.email == email).first():
            raise HTTPException(status_code=409,
                                detail="an account with that email already exists in "
                                       "your organization — sign in instead")
        req = (db.query(JoinRequest)
               .filter(JoinRequest.tenant_id == claim.tenant_id,
                       JoinRequest.email == email).first())
        if req is None:
            req = JoinRequest(tenant_id=claim.tenant_id, email=email,
                              password_hash=hash_password(body.password))
            db.add(req)
        elif req.status == "pending":
            raise HTTPException(status_code=409,
                                detail="a join request for that email is already "
                                       "awaiting approval")
        else:   # decided earlier — allow a fresh attempt with a fresh password
            req.status = "pending"
            req.password_hash = hash_password(body.password)
            req.email_verified = False
            req.decided_at = None
            req.decided_by = ""
        db.commit()
        db.refresh(req)

        from . import email as email_mod
        if email_mod.enabled():
            # Mailbox ownership isn't proven yet — park the request behind an emailed
            # confirm link. Even auto-approve waits for the click (that's the point).
            token = create_token({"typ": "join", "sub": str(req.id)}, ttl=86400)
            email_mod.send(
                email, f"Confirm your request to join {tenant.name or tenant.slug} on Palivane",
                f"Someone (hopefully you) asked to join the \"{tenant.name or tenant.slug}\" "
                f"organization on Palivane as {email}.\n\n"
                f"Confirm it here (link valid for 24 hours):\n"
                f"{email_mod.base_url()}/api/auth/join/confirm?token={token}\n\n"
                "If this wasn't you, ignore this email and nothing will happen.")
            return {"status": "confirm_email", "org": tenant.name or tenant.slug}
        if claim.auto_approve:
            user = domains_mod.approve(db, req, f"auto ({claim.domain})")
            return _session_payload(user, tenant)
        return {"status": "pending_approval", "org": tenant.name or tenant.slug}

    slug = _unique_slug(db, _slugify(body.slug or body.org_name))
    # A hosted signup starts a full-featured trial; the source-available self-host path is
    # what stays free indefinitely (see app/plans.py).
    trial_days = settings.trial_days
    tenant = Tenant(
        slug=slug, name=body.org_name.strip() or slug,
        plan="trial" if trial_days > 0 else "free",
        trial_ends_at=(_naive_utc() + timedelta(days=trial_days)) if trial_days > 0 else None)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    from . import email as email_mod
    verify = email_mod.enabled()   # require mailbox proof when we can send it
    user = User(tenant_id=tenant.id, email=email,
                password_hash=hash_password(body.password), role="admin",
                email_verified=not verify)
    db.add(user)
    db.commit()
    db.refresh(user)
    if verify:
        token = create_token({"typ": "email_verify", "sub": str(user.id)}, ttl=86400)
        email_mod.send(
            email, "Verify your Palivane account",
            f"Welcome to Palivane. Confirm this address to activate your new organization "
            f"\"{tenant.name or tenant.slug}\" (link valid for 24 hours):\n\n"
            f"{email_mod.base_url()}/api/auth/verify?token={token}\n\n"
            "If you didn't sign up, ignore this email.")
        return {"status": "verify_email", "org": tenant.name or tenant.slug}
    return _session_payload(user, tenant)


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Honors X-Forwarded-For (first hop) behind a load balancer."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def _throttled(db: Session, email: str, ip: str) -> bool:
    """DB-backed brute-force check (shared across workers/replicas). Blocks if this email
    OR this IP has too many recent failures. Prunes rows past the window."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.login_window)
    db.query(LoginAttempt).filter(LoginAttempt.created_at < cutoff).delete()
    db.commit()
    by_email = db.query(LoginAttempt).filter(
        LoginAttempt.email == email, LoginAttempt.created_at >= cutoff).count()
    if by_email >= settings.login_max_fails:
        return True
    if ip:
        by_ip = db.query(LoginAttempt).filter(
            LoginAttempt.ip == ip, LoginAttempt.created_at >= cutoff).count()
        if by_ip >= settings.login_ip_max_fails:
            return True
    return False


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    ip = _client_ip(request)
    if _throttled(db, email, ip):
        raise HTTPException(status_code=429,
                            detail="too many failed attempts, try again later")

    q = db.query(User).filter(User.email == email, User.active.is_(True))
    if body.org.strip():
        # Tenant-scoped login (multi-tenant): resolve the org and pin the user to it.
        tenant = db.query(Tenant).filter(Tenant.slug == body.org.strip().lower()).first()
        q = q.filter(User.tenant_id == tenant.id) if tenant else q.filter(User.id == -1)
    matches = q.limit(2).all()
    # Email alone is unique only within a tenant; if it matches more than one org, the
    # caller must specify `org` (never auto-pick — that would be a cross-tenant hazard).
    user = matches[0] if len(matches) == 1 else None
    ambiguous = len(matches) > 1

    # Verify even on miss to keep timing uniform; never reveal which factor failed.
    ok = verify_password(body.password, user.password_hash if user else DUMMY_PASSWORD_HASH)
    if ambiguous:
        raise HTTPException(status_code=409,
                            detail="multiple organizations use this email, specify your org")
    if not user or not ok:
        db.add(LoginAttempt(email=email, ip=ip))
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")

    from .lifecycle import ensure_active
    ensure_active(db, user.tenant_id)
    if not user.email_verified:
        raise HTTPException(status_code=403,
                            detail="verify your email first, check your inbox for the "
                                   "confirmation link")

    # Successful login clears this email's recent failures.
    db.query(LoginAttempt).filter(LoginAttempt.email == email).delete()
    # Transparently upgrade legacy (PBKDF2) hashes to argon2id on successful login.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    db.commit()

    if user.mfa_enabled:
        # Password verified, but MFA is on — issue a short-lived challenge, not a session.
        challenge = create_token({"typ": "mfa", "sub": str(user.id), "tv": user.token_version},
                                 ttl=300)
        return {"mfa_required": True, "challenge": challenge}

    return _session_response(user)


def _session_response(user: User) -> dict:
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version})
    return {"access_token": token, "token_type": "bearer", "user": user.to_dict()}


@router.post("/auth/forgot")
def forgot_password(body: ForgotRequest, request: Request, db: Session = Depends(get_db)):
    """Email a password-reset link. ALWAYS returns 200 with the same body — the response
    must not reveal whether an account exists. Reuses the login throttle so this can't be
    used as an email-spam cannon; throttled requests silently skip the send."""
    from . import email as email_mod
    email_addr = body.email.lower().strip()
    ip = _client_ip(request)
    if not email_mod.enabled() or _throttled(db, email_addr, ip):
        return {"ok": True}
    db.add(LoginAttempt(email=email_addr, ip=ip))   # count toward the throttle window
    db.commit()

    q = db.query(User).filter(User.email == email_addr, User.active.is_(True))
    if body.org.strip():
        tenant = db.query(Tenant).filter(Tenant.slug == body.org.strip().lower()).first()
        q = q.filter(User.tenant_id == tenant.id) if tenant else q.filter(User.id == -1)
    for user in q.limit(5).all():   # one reset link per matching account (multi-org emails)
        tenant = db.get(Tenant, user.tenant_id)
        if tenant is None or tenant.status == "suspended":
            continue
        token = create_token({"typ": "pwreset", "sub": str(user.id),
                              "tv": user.token_version}, ttl=1800)
        email_mod.send(
            user.email, "Reset your Palivane password",
            f"A password reset was requested for your Palivane account "
            f"({user.email}, organization \"{tenant.slug}\").\n\n"
            f"Reset it here (link valid for 30 minutes):\n"
            f"{email_mod.base_url()}/#reset={token}\n\n"
            "If you didn't request this, you can ignore this email — "
            "your password is unchanged.")
    return {"ok": True}


@router.post("/auth/reset")
def reset_password(body: ResetRequest, db: Session = Depends(get_db)):
    """Set a new password from a reset token. Bumps token_version, which both revokes
    every existing session and makes the link single-use (its `tv` no longer matches)."""
    try:
        payload = decode_token(body.token)
    except TokenError:
        raise HTTPException(status_code=400, detail="invalid or expired reset link")
    if payload.get("typ") != "pwreset":
        raise HTTPException(status_code=400, detail="invalid or expired reset link")
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.active or int(payload.get("tv", -1)) != user.token_version:
        raise HTTPException(status_code=400, detail="invalid or expired reset link")
    from .lifecycle import ensure_active
    ensure_active(db, user.tenant_id)
    user.password_hash = hash_password(body.password)
    user.token_version += 1
    db.query(LoginAttempt).filter(LoginAttempt.email == user.email).delete()
    db.commit()
    audit_log.record(db, user.tenant_id, user.email, "user.password_reset", target=user.email)
    return {"ok": True}


@router.get("/auth/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    """Landing for the new-org signup verification link. Marks the mailbox proven and
    redirects to the console with a status fragment (it's opened from an inbox)."""
    from fastapi.responses import RedirectResponse
    from . import email as email_mod
    base = email_mod.base_url()
    try:
        payload = decode_token(token)
    except TokenError:
        return RedirectResponse(f"{base}/#verified=bad")
    if payload.get("typ") != "email_verify":
        return RedirectResponse(f"{base}/#verified=bad")
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.active:
        return RedirectResponse(f"{base}/#verified=bad")
    if not user.email_verified:
        user.email_verified = True
        db.commit()
        audit_log.record(db, user.tenant_id, user.email, "user.email_verified", target=user.email)
    return RedirectResponse(f"{base}/#verified=ok")


@router.post("/auth/mfa/verify")
def mfa_verify(body: MFAVerify, request: Request, db: Session = Depends(get_db)):
    """Second factor: exchange the login MFA challenge + a TOTP/recovery code for a session."""
    try:
        payload = decode_token(body.challenge)
    except TokenError:
        raise HTTPException(status_code=400, detail="invalid or expired MFA challenge")
    if payload.get("typ") != "mfa":
        raise HTTPException(status_code=400, detail="invalid MFA challenge")
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.active or not user.mfa_enabled:
        raise HTTPException(status_code=401, detail="invalid credentials")

    ip = _client_ip(request)
    if _throttled(db, user.email, ip):
        raise HTTPException(status_code=429, detail="too many attempts, try again later")

    ok = False
    step = totp.verify_step(decrypt(user.mfa_secret), body.code)
    if step is not None:
        # Reject a code from a step already used (replay within the validity window).
        if step > (user.mfa_last_step or 0):
            user.mfa_last_step = step
            ok = True
    else:
        remaining = totp.consume_recovery(user.mfa_recovery or [], body.code)
        if remaining is not None:
            user.mfa_recovery = remaining   # one-time use
            ok = True
    if not ok:
        db.add(LoginAttempt(email=user.email, ip=ip))
        db.commit()
        raise HTTPException(status_code=401, detail="invalid code")

    db.query(LoginAttempt).filter(LoginAttempt.email == user.email).delete()
    db.commit()
    return _session_response(user)


@router.get("/auth/me")
def me(request: Request, current: User = Depends(get_current_user),
       db: Session = Depends(get_db)):
    tenant = db.get(Tenant, current.tenant_id)
    # `demo` comes from the session token's own claim (app/demo.py mints it, and
    # get_current_user already enforces it as read-only), so it is true for as long as the
    # session is, across reloads and new tabs — which a client-side flag was not.
    return {"user": current.to_dict(), "tenant": tenant.to_dict() if tenant else None,
            "demo": bool(getattr(request.state, "demo_session", False))}


@router.post("/auth/logout-all")
def logout_all(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke every existing session token for the current user (e.g. after a suspected
    compromise). Bumps token_version so all previously issued JWTs stop validating."""
    current.token_version = (current.token_version or 0) + 1
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "session.revoke_all")
    return {"revoked": True, "token_version": current.token_version}


@router.post("/auth/mfa/setup")
def mfa_setup(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Begin TOTP enrollment: store a fresh secret (not yet active) and return it + the
    otpauth:// URI to add to an authenticator app. Confirm with a code to activate."""
    if current.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    secret = totp.generate_secret()
    current.mfa_secret = encrypt(secret)
    db.commit()
    return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, current.email)}


@router.post("/auth/mfa/confirm")
def mfa_confirm(body: MFACode, current: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """Activate MFA by proving a code from the enrolled secret. Returns recovery codes ONCE."""
    secret = decrypt(current.mfa_secret)
    if not secret:
        raise HTTPException(status_code=400, detail="run MFA setup first")
    if not totp.verify(secret, body.code):
        raise HTTPException(status_code=400, detail="invalid code")
    codes = totp.generate_recovery_codes()
    current.mfa_recovery = [totp.hash_code(c) for c in codes]
    current.mfa_enabled = True
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "mfa.enable")
    return {"mfa_enabled": True, "recovery_codes": codes}


@router.post("/auth/mfa/disable")
def mfa_disable(body: MFACode, current: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """Turn off MFA — requires a current TOTP or an unused recovery code."""
    if not current.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    ok = totp.verify(decrypt(current.mfa_secret), body.code) or \
        totp.consume_recovery(current.mfa_recovery or [], body.code) is not None
    if not ok:
        raise HTTPException(status_code=400, detail="invalid code")
    current.mfa_enabled = False
    current.mfa_secret = ""
    current.mfa_recovery = []
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "mfa.disable")
    return {"mfa_enabled": False}


@router.get("/users")
def list_users(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(User).filter(User.tenant_id == current.tenant_id).all()
    return {"users": [u.to_dict() for u in rows]}


@router.get("/audit")
def list_audit(current: User = Depends(require_admin), db: Session = Depends(get_db),
               limit: int = 100, action: str | None = None):
    """The tenant's admin audit trail (newest first). Optional `action` filter."""
    return {"entries": audit_log.recent(db, current.tenant_id, limit=limit, action=action)}


@router.post("/users")
def create_user(body: UserCreate, current: User = Depends(require_admin), db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    exists = (
        db.query(User)
        .filter(User.tenant_id == current.tenant_id, User.email == email)
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="a user with that email already exists")
    from .metering import check_resource_quota
    check_resource_quota(db, current.tenant_id, "users",
                         db.query(User).filter(User.tenant_id == current.tenant_id).count())
    from . import email as email_mod
    invite = not body.password
    if invite and not email_mod.enabled():
        raise HTTPException(status_code=400,
                            detail="a password is required (email invites are not "
                                   "configured on this deployment)")
    if not invite and len(body.password) < 8:
        raise HTTPException(status_code=422, detail="password must be at least 8 characters")
    user = User(
        tenant_id=current.tenant_id, email=email,
        # Invited users get an unguessable placeholder; only the emailed set-password
        # link (below) can turn this into a usable login.
        password_hash=hash_password(body.password or secrets.token_urlsafe(32)),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    if invite:
        tenant = db.get(Tenant, current.tenant_id)
        token = create_token({"typ": "pwreset", "sub": str(user.id),
                              "tv": user.token_version}, ttl=259200)   # 3 days
        email_mod.send(
            email, f"You've been invited to {tenant.name or tenant.slug} on Palivane",
            f"{current.email} invited you to the \"{tenant.name or tenant.slug}\" "
            f"organization on Palivane as {body.role}.\n\n"
            f"Set your password to activate the account (link valid for 3 days):\n"
            f"{email_mod.base_url()}/#reset={token}\n\n"
            "If you weren't expecting this, you can ignore it.")
    audit_log.record(db, current.tenant_id, current.email, "user.create",
                     target=email, detail={"role": body.role, "invite": invite})
    return user.to_dict() | {"invited": invite}


def _active_admin_count(db: Session, tenant_id: int) -> int:
    return (
        db.query(User)
        .filter(User.tenant_id == tenant_id, User.role == "admin", User.active.is_(True))
        .count()
    )


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, current: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    """Change a user's role (promote/demote) or login access (active). Admin only,
    same-tenant only. Guards against locking yourself out or removing the last admin."""
    user = db.get(User, user_id)
    if user is None or user.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="user not found")

    demoting = body.role is not None and body.role != "admin" and user.role == "admin"
    deactivating = body.active is False and user.active

    # You can't strip your own access — someone else must do it.
    if user.id == current.id:
        if demoting:
            raise HTTPException(status_code=400, detail="you cannot remove your own admin role")
        if deactivating:
            raise HTTPException(status_code=400, detail="you cannot deactivate your own account")

    # Never leave the tenant with zero active admins.
    if (demoting or (deactivating and user.role == "admin")) and _active_admin_count(db, current.tenant_id) <= 1:
        raise HTTPException(status_code=400, detail="cannot remove the last active admin")

    if body.role is not None:
        user.role = body.role
    if body.active is not None:
        user.active = body.active
    db.commit()
    db.refresh(user)
    audit_log.record(db, current.tenant_id, current.email, "user.update",
                     target=user.email, detail={"role": user.role, "active": user.active})
    return user.to_dict()


@router.post("/extension/token")
def extension_token(device: str = "", current: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """Mint (or re-issue) a per-user, tenant-scoped capture key for the browser extension
    (self-serve / BYOD sign-in via the console). Any authenticated user can bind their own
    extension; attributed to their email for per-user findings, and revocable in the console
    like any API key. The console's /extension-connect page calls this after login/SSO and
    hands the token back to the extension via the OAuth redirect.

    Dedup: re-connecting the same device rotates that device's existing key in place instead
    of piling up a new row on every sign-in. `device` (browser deviceId / palivane-connect
    hostname) scopes the key so separate machines keep separate, independently-revocable keys;
    when it's absent we fall back to a single per-user "browser-extension" key."""
    dev = (device or "").strip()[:64]
    label = f"capture:{dev}" if dev else "browser-extension"
    token, prefix, token_hash = generate_api_key()
    existing = (db.query(ApiKey)
                .filter(ApiKey.tenant_id == current.tenant_id,
                        ApiKey.actor == current.email,
                        ApiKey.label == label,
                        ApiKey.active.is_(True))
                .order_by(ApiKey.id.desc()).first())
    if existing is not None:
        # Rotate the same row: the old token stops working, the fresh one is handed back,
        # and the device keeps one key instead of accumulating.
        existing.prefix, existing.token_hash = prefix, token_hash
        key = existing
        action = "extension.reconnect"
    else:
        key = ApiKey(tenant_id=current.tenant_id, label=label,
                     actor=current.email, prefix=prefix, token_hash=token_hash)
        db.add(key)
        action = "extension.connect"
    db.commit()
    db.refresh(key)
    audit_log.record(db, current.tenant_id, current.email, action,
                     target=current.email)
    # upstream_forwards: whether gateway-routed Claude Code will reach a real model or the
    # inspection stub — palivane-connect relays this as a "set your provider key" warning.
    # enforce: the org's stance for the local capture planes (Settings → Enforcement) —
    # palivane-connect provisions it into the hooks it installs.
    tenant = db.get(Tenant, current.tenant_id)
    enforce = tenant.client_enforce if tenant and tenant.client_enforce is not None \
        else settings.client_enforce
    # Staged enforcement: a policy override for this user (any tool) beats the org stance.
    from .models import PolicyOverride
    from .policies import resolve_enforce
    overrides = (db.query(PolicyOverride)
                   .filter(PolicyOverride.tenant_id == current.tenant_id).all())
    enforce, _ = resolve_enforce(bool(enforce), current.email, overrides)
    return {"token": token, "actor": current.email, "tenant": current.tenant_id,
            "enforce": bool(enforce),
            "upstream_forwards": upstream_forwards("anthropic", current.tenant_id, db)}


@router.post("/apikeys")
def create_api_key(body: ApiKeyCreate, current: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    """Mint a long-lived API key for a machine client (gateway/SIEM). The plaintext is
    returned ONCE — only its hash is stored."""
    from .metering import check_resource_quota
    check_resource_quota(db, current.tenant_id, "api_keys",
                         db.query(ApiKey).filter(ApiKey.tenant_id == current.tenant_id,
                                                 ApiKey.active.is_(True)).count())
    token, prefix, token_hash = generate_api_key()
    expires_at = None
    if body.expires_in_days:
        expires_at = _naive_utc() + timedelta(days=body.expires_in_days)
    key = ApiKey(tenant_id=current.tenant_id, label=body.label, actor=body.actor,
                 prefix=prefix, token_hash=token_hash, expires_at=expires_at)
    db.add(key)
    db.commit()
    db.refresh(key)
    audit_log.record(db, current.tenant_id, current.email, "apikey.create",
                     target=body.label or body.actor)
    return {**key.to_dict(), "token": token}


@router.get("/apikeys")
def list_api_keys(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(ApiKey.tenant_id == current.tenant_id).all()
    return {"api_keys": [k.to_dict() for k in rows]}


@router.delete("/apikeys/{key_id}")
def revoke_api_key(key_id: int, current: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if key is None or key.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="api key not found")
    key.active = False
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "apikey.revoke",
                     target=key.label or str(key_id))
    return {"id": key_id, "active": False}


# --- Agent identity (Phase 0: verifiable identity + attribution) ----------------------

def _assert_oidc_subject_free(db: Session, tenant_id: int, subject: str, exclude_id=None) -> None:
    """A workload OIDC subject maps a JWT to exactly one agent, so it must be unique within a
    tenant — otherwise auth would resolve to an arbitrary agent."""
    if not subject:
        return
    q = db.query(Agent).filter(Agent.tenant_id == tenant_id, Agent.oidc_subject == subject)
    if exclude_id is not None:
        q = q.filter(Agent.id != exclude_id)
    if q.first():
        raise HTTPException(status_code=409, detail=f"oidc_subject '{subject}' is already in use")


@router.post("/agents")
def create_agent(body: AgentCreate, current: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """Register an AI agent and mint its `ag_…` identity token (returned ONCE — only the
    hash is stored). The agent presents this token on capture requests so its actions are
    attributed to it; role is reserved for the least-privilege phase."""
    if db.query(Agent).filter(Agent.tenant_id == current.tenant_id,
                              Agent.name == body.name.strip()).first():
        raise HTTPException(status_code=409, detail="an agent with that name already exists")
    _assert_oidc_subject_free(db, current.tenant_id, body.oidc_subject.strip())
    token, prefix, token_hash = generate_agent_token()
    agent = Agent(tenant_id=current.tenant_id, name=body.name.strip(), kind=body.kind,
                  role=body.role.strip(), oidc_subject=body.oidc_subject.strip(),
                  prefix=prefix, token_hash=token_hash)
    db.add(agent)
    db.commit()
    db.refresh(agent)
    audit_log.record(db, current.tenant_id, current.email, "agent.create", target=agent.name)
    return {**agent.to_dict(), "token": token}


@router.get("/agents")
def list_agents(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(Agent).filter(Agent.tenant_id == current.tenant_id).order_by(Agent.name).all()
    return {"agents": [a.to_dict() for a in rows]}


@router.post("/agents/{agent_id}/rotate")
def rotate_agent(agent_id: int, current: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """Rotate an agent's token — issues a new `ag_…` (old one stops working immediately)."""
    agent = db.get(Agent, agent_id)
    if agent is None or agent.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="agent not found")
    token, prefix, token_hash = generate_agent_token()
    agent.prefix, agent.token_hash, agent.active = prefix, token_hash, True
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "agent.rotate", target=agent.name)
    return {**agent.to_dict(), "token": token}


@router.patch("/agents/{agent_id}")
def update_agent(agent_id: int, body: AgentUpdate, current: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """Assign (or clear) an agent's least-privilege role."""
    agent = db.get(Agent, agent_id)
    if agent is None or agent.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="agent not found")
    if body.role is not None:
        role = body.role.strip()
        if role and not db.query(AgentRole).filter(AgentRole.tenant_id == current.tenant_id,
                                                   AgentRole.name == role).first():
            raise HTTPException(status_code=400, detail=f"no such role '{role}'")
        agent.role = role
        audit_log.record(db, current.tenant_id, current.email, "agent.role",
                         target=f"{agent.name}={role or '-'}")
    if body.deny is not None:
        agent.deny = ",".join(dict.fromkeys(x.strip() for x in body.deny if x.strip()))
    if body.oidc_subject is not None:
        sub = body.oidc_subject.strip()
        _assert_oidc_subject_free(db, current.tenant_id, sub, exclude_id=agent.id)
        if sub != (agent.oidc_subject or ""):
            audit_log.record(db, current.tenant_id, current.email, "agent.oidc_subject",
                             target=f"{agent.name}={sub or '-'}")
        agent.oidc_subject = sub
    if body.rate_limit is not None:
        agent.rate_limit = body.rate_limit
    if body.block_severity is not None:
        agent.block_severity = body.block_severity
    db.commit()
    return agent.to_dict()


@router.post("/agents/{agent_id}/token")
def mint_agent_token(agent_id: int, body: AgentTokenRequest,
                     current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Mint a short-lived agent session token (JWT, TTL <= 24h) for gateway calls.

    Lets the long-lived `ag_…` credential stay locked away (e.g. used only by a deploy
    system at startup) while the running workload holds a token that expires on its own —
    a leaked session token is worth minutes, not forever. Disabling the agent revokes all
    its session tokens immediately (the gateway re-checks `active` on every request)."""
    agent = db.get(Agent, agent_id)
    if agent is None or agent.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="agent not found")
    if not agent.active:
        raise HTTPException(status_code=400, detail="agent is disabled")
    from .security import create_token
    token = create_token({"typ": "agent", "agent_id": agent.id, "tenant": agent.tenant_id},
                         ttl=body.ttl_minutes * 60)
    audit_log.record(db, current.tenant_id, current.email, "agent.token",
                     target=f"{agent.name} ttl={body.ttl_minutes}m")
    return {"token": token, "expires_in": body.ttl_minutes * 60, "agent": agent.name}


@router.delete("/agents/{agent_id}")
def disable_agent(agent_id: int, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None or agent.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="agent not found")
    agent.active = False
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "agent.disable", target=agent.name)
    return {"id": agent_id, "active": False}


# --- Agent roles (least-privilege, Phase 1) ------------------------------------------

def _apply_role(role: AgentRole, body: AgentRoleIn) -> None:
    _j = lambda xs: ",".join(dict.fromkeys(s.strip() for s in xs if s.strip()))
    role.allow_tools = _j(body.allow_tools)
    role.allow_servers = _j(body.allow_servers)
    role.allow_commands = _j(body.allow_commands)
    role.deny = _j(body.deny)
    role.data_scopes = _j(body.data_scopes)
    role.default_allow = bool(body.default_allow)
    role.enforce = bool(body.enforce)


@router.post("/agent-roles")
def upsert_agent_role(body: AgentRoleIn, current: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    """Create or update a least-privilege role (by name). enforce=false is monitor-only."""
    role = (db.query(AgentRole).filter(AgentRole.tenant_id == current.tenant_id,
                                       AgentRole.name == body.name.strip()).one_or_none())
    if role is None:
        role = AgentRole(tenant_id=current.tenant_id, name=body.name.strip())
        db.add(role)
    _apply_role(role, body)
    db.commit(); db.refresh(role)
    audit_log.record(db, current.tenant_id, current.email, "agentrole.upsert", target=role.name)
    return role.to_dict()


@router.get("/agent-roles")
def list_agent_roles(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(AgentRole).filter(AgentRole.tenant_id == current.tenant_id).order_by(AgentRole.name).all()
    return {"roles": [r.to_dict() for r in rows]}


@router.delete("/agent-roles/{role_id}")
def delete_agent_role(role_id: int, current: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    role = db.get(AgentRole, role_id)
    if role is None or role.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="role not found")
    # Unassign it from any agents so their calls fall back to no-role (allowed).
    db.query(Agent).filter(Agent.tenant_id == current.tenant_id, Agent.role == role.name)\
        .update({Agent.role: ""})
    db.delete(role); db.commit()
    audit_log.record(db, current.tenant_id, current.email, "agentrole.delete", target=role.name)
    return {"ok": True}


# --- device enrollment (per-device self-registration) --------------------------------

@router.post("/enroll/tokens")
def create_enrollment_token(body: EnrollmentTokenCreate, current: User = Depends(require_admin),
                            db: Session = Depends(get_db)):
    """Mint an enrollment token. A device presents it once to POST /api/enroll and gets
    its own per-device API key — so machines self-register without embedding a shared key."""
    token, prefix, token_hash = generate_enrollment_token()
    expires_at = _naive_utc() + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    et = EnrollmentToken(tenant_id=current.tenant_id, label=body.label, prefix=prefix,
                         token_hash=token_hash, max_uses=body.max_uses, expires_at=expires_at)
    db.add(et)
    db.commit()
    db.refresh(et)
    audit_log.record(db, current.tenant_id, current.email, "enroll_token.create", target=body.label)
    return {**et.to_dict(), "token": token}


@router.get("/enroll/tokens")
def list_enrollment_tokens(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(EnrollmentToken).filter(EnrollmentToken.tenant_id == current.tenant_id).all()
    return {"enrollment_tokens": [t.to_dict() for t in rows]}


@router.delete("/enroll/tokens/{token_id}")
def revoke_enrollment_token(token_id: int, current: User = Depends(require_admin),
                            db: Session = Depends(get_db)):
    et = db.get(EnrollmentToken, token_id)
    if et is None or et.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="enrollment token not found")
    et.active = False
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "enroll_token.revoke", target=str(token_id))
    return {"id": token_id, "active": False}


@router.post("/enroll")
def enroll(body: EnrollRequest, db: Session = Depends(get_db)):
    """Device self-registration: present an enrollment token, receive a per-device API key.
    Public (no user auth) — the enrollment token is the credential. Returns an `ak_` key
    bound to the token's tenant and attributed to the device identity."""
    et = (
        db.query(EnrollmentToken)
        .filter(EnrollmentToken.prefix == body.token[:11], EnrollmentToken.active.is_(True))
        .first()
    )
    if et is None or not hmac.compare_digest(et.token_hash, hash_token(body.token)):
        raise HTTPException(status_code=401, detail="invalid enrollment token")
    if et.expires_at and et.expires_at < _naive_utc():
        raise HTTPException(status_code=401, detail="enrollment token expired")

    # Atomically claim one use: a single conditional UPDATE gated on uses < max_uses, so
    # concurrent requests can't each pass a check-then-increment race and over-redeem a
    # (e.g. max_uses=1) token into many device keys.
    claimed = (
        db.query(EnrollmentToken)
        .filter(EnrollmentToken.id == et.id, EnrollmentToken.active.is_(True),
                (EnrollmentToken.max_uses.is_(None)) | (EnrollmentToken.uses < EnrollmentToken.max_uses))
        .update({EnrollmentToken.uses: EnrollmentToken.uses + 1}, synchronize_session=False)
    )
    if not claimed:
        db.rollback()
        raise HTTPException(status_code=401, detail="enrollment token exhausted")

    from .metering import check_resource_quota
    check_resource_quota(db, et.tenant_id, "api_keys",
                         db.query(ApiKey).filter(ApiKey.tenant_id == et.tenant_id,
                                                 ApiKey.active.is_(True)).count())
    token, prefix, token_hash = generate_api_key()
    # Attribute to the email-shaped user when the enroller supplied one (reconciles against
    # the SSO/email shadow set); else fall back to the device string. Label always names the
    # device so the key is traceable to a machine regardless.
    key = ApiKey(tenant_id=et.tenant_id, label=f"device:{body.device}",
                 actor=(body.user or body.device), prefix=prefix, token_hash=token_hash)
    db.add(key)
    db.commit()
    audit_log.record(db, et.tenant_id, body.device, "device.enroll", target=body.device)
    # ANTHROPIC_BASE_URL takes the bare origin — the Anthropic SDK appends /v1/messages
    # itself, so a "/v1" suffix here would double it into /v1/v1/messages (405). No suffix.
    return {"token": token, "actor": body.device, "base_url_suffix": ""}


@router.get("/enroll/check")
def enroll_check(x_palivane_token: str = Header(default=""), db: Session = Depends(get_db)):
    """Cheap liveness check for a device key (`ak_…`): 200 if still valid, 401 if revoked
    or rotated. Lets the CLI apiKeyHelper (palivane-reenroll) tell "my cached key is dead,
    re-enroll" from "still good" without spending a gateway/ingest call or burning quota."""
    from .gateway import _resolve_api_key
    principal = _resolve_api_key(x_palivane_token, db)   # raises 401 on a bad/expired key
    return {"ok": True, "actor": principal.actor}


# --- per-tenant upstream provider config (gateway billing isolation) -----------------

def _upstream_state(provider: str, tenant_id: int, db: Session) -> dict:
    row = (db.query(TenantUpstream)
           .filter(TenantUpstream.tenant_id == tenant_id, TenantUpstream.provider == provider)
           .first())
    return {
        "provider": provider,
        "base_url": row.base_url if row else "",
        "key_set": bool(row and row.key_encrypted),   # never return the key itself
        "effective": "tenant" if row and (row.base_url or row.key_encrypted) else "global",
        "forwards": upstream_forwards(provider, tenant_id, db),
    }


@router.get("/upstreams")
def list_upstreams(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Per-tenant gateway upstreams. Shows base URL and whether a key is set (never the
    key), and whether the provider will forward (tenant config or global fallback)."""
    return {"upstreams": [_upstream_state(p, current.tenant_id, db) for p in PROVIDERS]}


@router.put("/upstreams/{provider}")
def set_upstream(provider: str, body: UpstreamConfig, current: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """Set this org's own provider account for gateway forwarding (key stored encrypted).
    An empty `key` leaves the existing key untouched (e.g. to change only base_url)."""
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail=f"unknown provider (expected one of {', '.join(PROVIDERS)})")
    row = (db.query(TenantUpstream)
           .filter(TenantUpstream.tenant_id == current.tenant_id, TenantUpstream.provider == provider)
           .first())
    base = body.base_url.strip()
    if base:
        from .netguard import is_safe_url_static
        if not is_safe_url_static(base):
            raise HTTPException(status_code=400,
                                detail="base_url must be an https(s) URL to a public host "
                                       "(private/loopback/metadata addresses are blocked)")
    if row is None:
        row = TenantUpstream(tenant_id=current.tenant_id, provider=provider)
        db.add(row)
    row.base_url = base
    if body.key:
        row.key_encrypted = crypto.seal_secret(crypto.dek_for(db, row.tenant_id), body.key)
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "upstream.set", target=provider)
    return _upstream_state(provider, current.tenant_id, db)


@router.delete("/upstreams/{provider}")
def delete_upstream(provider: str, current: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """Remove this org's provider config; the gateway falls back to the global default."""
    row = (db.query(TenantUpstream)
           .filter(TenantUpstream.tenant_id == current.tenant_id, TenantUpstream.provider == provider)
           .first())
    if row is not None:
        db.delete(row)
        db.commit()
    audit_log.record(db, current.tenant_id, current.email, "upstream.delete", target=provider)
    return {"provider": provider, "effective": "global"}


# --- BYOK judge key (the org pays for its own judge inference) -----------------------

_JUDGE_BYOK_PROVIDERS = ("anthropic", "openai", "gemini")


def _judge_key_state(tenant) -> dict:
    # `health` is this key's live judge state (ok False = the org's key is failing and
    # its verdicts run on offline detectors only) — surfaced HERE, to the tenant,
    # because BYOK failures deliberately never page the operator. None until a scan
    # has exercised the key on this instance.
    health = None
    if tenant.judge_byok_key_encrypted:
        from .detectors.llm_judge import byok_health
        try:
            # no session in this helper, and none is needed: opening an existing DEK
            # takes only the KEK. (A minting call here would have raised NameError into
            # the except below and silently reported health as None.)
            key = crypto.unseal_secret(tenant.judge_byok_key_encrypted,
                                       crypto.tenant_dek_readonly(tenant))
            health = byok_health(tenant.judge_byok_provider or "", key,
                                 tenant.judge_byok_model or "")
        except Exception:
            health = None
    return {"provider": tenant.judge_byok_provider or "",
            "model": tenant.judge_byok_model or "",
            "key_set": bool(tenant.judge_byok_key_encrypted),
            "health": health}


@router.get("/judge-key")
def get_judge_key(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """This org's own judge API key config: provider, model, and whether a key is set
    (never the key). With a key set, the LLM judge runs for this org on its own bill —
    independent of the operator's judge and exempt from plan gating."""
    return _judge_key_state(db.get(Tenant, current.tenant_id))


@router.put("/judge-key")
def set_judge_key(body: JudgeKeyConfig, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Set the org's own judge key (stored encrypted, write-only). An empty `key`
    keeps the existing one (e.g. to change only provider/model — note a key minted for
    one provider won't authenticate against another)."""
    provider = (body.provider or "").strip().lower()
    if provider not in _JUDGE_BYOK_PROVIDERS:
        raise HTTPException(status_code=404,
                            detail=f"unknown provider (expected one of {', '.join(_JUDGE_BYOK_PROVIDERS)})")
    tenant = db.get(Tenant, current.tenant_id)
    tenant.judge_byok_provider = provider
    tenant.judge_byok_model = (body.model or "").strip()
    if body.key:
        tenant.judge_byok_key_encrypted = crypto.seal_secret(
            crypto.tenant_dek(tenant, db), body.key.strip())
    if not tenant.judge_byok_key_encrypted:
        raise HTTPException(status_code=400, detail="key is required (none stored yet)")
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "judge_key.set", target=provider)
    return _judge_key_state(tenant)


@router.delete("/judge-key")
def delete_judge_key(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Remove the org's own judge key; the judge reverts to the operator's global
    config (subject to plan gating), or off if the operator runs none."""
    tenant = db.get(Tenant, current.tenant_id)
    tenant.judge_byok_provider = ""
    tenant.judge_byok_key_encrypted = ""
    tenant.judge_byok_model = ""
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "judge_key.delete")
    return _judge_key_state(tenant)


# --- tenant settings & lifecycle (data control) --------------------------------------

_JUDGE = {"on": True, "off": False, "inherit": None}


@router.post("/scim/token")
def scim_token_mint(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Mint (or rotate) the org's SCIM 2.0 bearer token. Plaintext is returned exactly
    once — only its hash is stored. Point the IdP at /scim/v2 with this token."""
    from . import audit_log
    from .scim import mint_token
    tenant = db.get(Tenant, current.tenant_id)
    rotated = bool(tenant.scim_token_hash)
    token = mint_token(db, tenant)
    db.commit()
    audit_log.record(db, current.tenant_id, current.email,
                     "scim.token_rotated" if rotated else "scim.token_minted")
    return {"token": token, "base_url": "/scim/v2", "rotated": rotated}


@router.delete("/scim/token")
def scim_token_revoke(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Revoke the org's SCIM token — provisioning stops until a new one is minted."""
    from . import audit_log
    tenant = db.get(Tenant, current.tenant_id)
    tenant.scim_token_hash = ""
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "scim.token_revoked")
    return {"ok": True}


@router.patch("/tenant")
def update_tenant(body: TenantUpdate, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Org settings: display name, Claude-judge consent, and findings retention."""
    from .plans import require_feature
    tenant = db.get(Tenant, current.tenant_id)
    # Plan gates fire only when the request tries to ENABLE a gated feature (setting a
    # non-empty value) — clearing a leftover config is always allowed.
    if (body.alert_webhook or "").strip():
        require_feature(tenant, "alerts")
    if (body.siem_url or "").strip() or (body.siem_token or "").strip():
        require_feature(tenant, "siem")
    if any((getattr(body, f) or "").strip() for f in
           ("siem_s3_bucket", "siem_s3_key_id", "siem_s3_secret", "siem_s3_role_arn")):
        require_feature(tenant, "s3_delivery")
    if body.archive_s3_enabled:
        require_feature(tenant, "s3_delivery")
    if body.name is not None:
        tenant.name = body.name.strip() or tenant.name
    if body.judge is not None:
        tenant.judge_enabled = _JUDGE[body.judge]
    if body.store_content is not None:
        tenant.store_content = _JUDGE[body.store_content]   # reuse on/off/inherit -> True/False/None
    if body.ml_capture is not None:
        # Explicit consent flag for ML-corpus capture (no inherit; audit-logged below).
        tenant.ml_capture = body.ml_capture
    if body.weekly_report is not None:
        tenant.weekly_report = bool(body.weekly_report)
    if body.redact_mode is not None:
        tenant.redact_mode = _JUDGE[body.redact_mode]       # coaching mode (tri-state)
    if body.self_justify is not None:
        tenant.self_justify = _JUDGE[body.self_justify]     # justified-proceed (tri-state)
    if body.gateway_tokenize is not None:
        tenant.gateway_tokenize = _JUDGE[body.gateway_tokenize]
    if body.retention_days is not None:
        if body.retention_days < 0:
            raise HTTPException(status_code=400, detail="retention_days must be >= 0")
        tenant.retention_days = body.retention_days
    if body.rate_limit is not None:
        if body.rate_limit < 0:
            raise HTTPException(status_code=400, detail="rate_limit must be >= 0")
        tenant.rate_limit = body.rate_limit
    if body.ingest_rate_limit is not None:
        if body.ingest_rate_limit < 0:
            raise HTTPException(status_code=400, detail="ingest_rate_limit must be >= 0")
        tenant.ingest_rate_limit = body.ingest_rate_limit
    if body.mcp_allowed_servers is not None:
        tenant.mcp_allowed_servers = body.mcp_allowed_servers.strip()
    if body.ide_ext_allowed is not None:
        tenant.ide_ext_allowed = body.ide_ext_allowed.strip()
    if body.ide_ext_denylist is not None:
        tenant.ide_ext_denylist = body.ide_ext_denylist.strip()
    if body.dep_denylist is not None:
        tenant.dep_denylist = body.dep_denylist.strip()
    if body.alert_webhook is not None:
        webhook = body.alert_webhook.strip()
        if webhook:
            from .netguard import is_safe_url_static
            if not is_safe_url_static(webhook):
                raise HTTPException(status_code=400,
                                    detail="alert_webhook must be a public http(s) URL (no internal/loopback/metadata hosts)")
        tenant.alert_webhook = webhook
    if body.alert_min_severity is not None:
        if body.alert_min_severity not in ("low", "suspicious", "high", "critical"):
            raise HTTPException(status_code=400, detail="invalid alert_min_severity")
        tenant.alert_min_severity = body.alert_min_severity
    if body.alert_digest is not None:
        if body.alert_digest not in ("off", "hourly", "daily"):
            raise HTTPException(status_code=400, detail="invalid alert_digest")
        tenant.alert_digest = body.alert_digest
    # SIEM forwarding — SSRF-guarded at set time (early feedback) and again at send time.
    if body.siem_url is not None:
        siem = body.siem_url.strip()
        if siem:
            from .netguard import is_safe_url_static
            if not is_safe_url_static(siem):
                raise HTTPException(status_code=400,
                                    detail="siem_url must be a public http(s) URL (no internal/loopback/metadata hosts)")
        tenant.siem_url = siem
    if body.siem_token is not None:
        # Sealed at rest (enc:v1: tag) like other stored secrets; unsealed at send time.
        # Legacy plaintext rows keep working — unseal passes untagged values through.
        tenant.siem_token = crypto.seal_secret(crypto.tenant_dek(tenant, db),
                                               body.siem_token.strip())
    if body.siem_min_severity is not None:
        if body.siem_min_severity not in ("low", "suspicious", "high", "critical"):
            raise HTTPException(status_code=400, detail="invalid siem_min_severity")
        tenant.siem_min_severity = body.siem_min_severity
    if body.siem_format is not None:
        if body.siem_format not in ("json", "splunk_hec", "cef"):
            raise HTTPException(status_code=400, detail="invalid siem_format")
        tenant.siem_format = body.siem_format
    # SIEM S3 delivery config (creds set only when a non-empty value is provided → write-only).
    if body.siem_s3_bucket is not None:
        tenant.siem_s3_bucket = body.siem_s3_bucket.strip()
    if body.siem_s3_prefix is not None:
        tenant.siem_s3_prefix = body.siem_s3_prefix.strip()
    if body.siem_s3_region is not None:
        tenant.siem_s3_region = body.siem_s3_region.strip()
    if body.siem_s3_key_id:
        tenant.siem_s3_key_id = body.siem_s3_key_id.strip()
    if body.siem_s3_secret:
        tenant.siem_s3_secret = crypto.seal_secret(crypto.tenant_dek(tenant, db),
                                                   body.siem_s3_secret.strip())  # sealed at rest
    if body.siem_s3_role_arn is not None:
        arn = body.siem_s3_role_arn.strip()
        # Any AWS partition (aws / aws-us-gov / aws-cn), but it must be an IAM *role* —
        # a user/root ARN here would just fail at AssumeRole time with a worse message.
        if arn and not re.match(r"^arn:aws[a-z-]*:iam::\d{12}:role/.+", arn):
            raise HTTPException(status_code=400,
                                detail="siem_s3_role_arn must be an IAM role ARN "
                                       "(arn:aws:iam::<account-id>:role/<name>)")
        if arn and not settings.role_delivery_principal:
            # AssumeRole needs an AWS identity for this deployment to be assumed *from*
            # (a static principal or the federated WIF role). With neither there is none,
            # so accepting the ARN would leave the tenant looking configured while nothing
            # can ever be delivered.
            raise HTTPException(status_code=400,
                                detail="Role-based S3 delivery is not available on this "
                                       "deployment. Use an access key pair instead.")
        if arn and not (tenant.siem_s3_external_id or "").strip():
            # First role config: mint the external ID the customer's trust policy pins
            # (confused-deputy guard). Never regenerated on later saves — the trust
            # policy references it.
            tenant.siem_s3_external_id = "plv-" + secrets.token_hex(16)
        tenant.siem_s3_role_arn = arn    # "" clears -> static keys (if set) take over
    # Raw event archival (rides the S3 delivery config above; enabling is plan-gated).
    if body.archive_s3_enabled is not None:
        tenant.archive_s3_enabled = body.archive_s3_enabled
    if body.archive_s3_raw_content is not None:
        tenant.archive_s3_raw_content = body.archive_s3_raw_content
    if body.archive_s3_daily_mb is not None:
        if body.archive_s3_daily_mb < 0:
            raise HTTPException(status_code=400, detail="archive_s3_daily_mb must be >= 0")
        tenant.archive_s3_daily_mb = body.archive_s3_daily_mb
    if body.gateway_enforce is not None:
        tenant.gateway_enforce = _JUDGE[body.gateway_enforce]  # same tri-state mapping
    if body.client_enforce is not None:
        tenant.client_enforce = _JUDGE[body.client_enforce]
    for sev_field in ("gateway_block_severity", "mcp_block_severity", "ci_block_severity"):
        val = getattr(body, sev_field)
        if val is not None:
            if val not in ("", "low", "suspicious", "high", "critical"):
                raise HTTPException(status_code=400, detail=f"invalid {sev_field}")
            setattr(tenant, sev_field, val)  # "" clears the override -> inherit global
    if body.sanctioned_ai_tools is not None:
        tenant.sanctioned_ai_tools = body.sanctioned_ai_tools.strip()
    if body.disabled_checks is not None:
        from .policies import VALID_KEYS
        bad = [k for k in body.disabled_checks if k not in VALID_KEYS]
        if bad:
            raise HTTPException(status_code=400, detail=f"unknown policy check(s): {', '.join(bad[:5])}")
        tenant.disabled_checks = ",".join(dict.fromkeys(k for k in body.disabled_checks if k in VALID_KEYS))
    if body.oversharing_rules is not None:
        tenant.oversharing_rules = body.oversharing_rules.strip()
    for _f in ("agent_oidc_issuer", "agent_oidc_jwks", "agent_oidc_audience"):
        _v = getattr(body, _f)
        if _v is not None:
            setattr(tenant, _f, _v.strip())
    if body.tool_suppress is not None:
        cleaned = body.tool_suppress.strip()
        if any(":" not in seg for seg in cleaned.split(";") if seg.strip()):
            raise HTTPException(status_code=400,
                                detail="tool_suppress must be tool:category;tool:category")
        tenant.tool_suppress = cleaned
    if body.custom_pii_patterns is not None:
        # Validate each label=regex line compiles; reject a bad pattern rather than silently drop.
        import re as _re
        for line in body.custom_pii_patterns.replace(";", "\n").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            try:
                _re.compile(line.partition("=")[2].strip())
            except _re.error:
                raise HTTPException(status_code=400,
                                    detail=f"invalid regex in custom_pii_patterns: {line[:60]}")
        tenant.custom_pii_patterns = body.custom_pii_patterns.strip()
    db.commit()
    db.refresh(tenant)
    # Unknown keys are accepted by the schema but never written. Report them rather than
    # dropping them in silence: a misspelled setting used to return 200 having changed
    # nothing, so the caller believed it applied — the same lookup-miss-as-success shape
    # that hid retired fleet clients and empty Actions variables.
    ignored = sorted(body.model_extra or {})
    changed = {k: v for k, v in body.model_dump(exclude_none=True).items()
               if k in TenantUpdate.model_fields}
    audit_log.record(db, current.tenant_id, current.email, "tenant.update",
                     detail={**changed, **({"ignored_fields": ignored} if ignored else {})})
    out = tenant.to_dict()
    if ignored:
        out["ignored_fields"] = ignored
    return out


@router.delete("/tenant")
def delete_tenant(body: TenantDelete, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Delete this organization and ALL its data (GDPR "delete my org"). Irreversible —
    the caller must pass the tenant slug as `confirm`."""
    tenant = db.get(Tenant, current.tenant_id)
    if body.confirm != tenant.slug:
        raise HTTPException(status_code=400,
                            detail=f"to confirm deletion, pass confirm=\"{tenant.slug}\"")
    slug = tenant.slug
    # The cascade lives in lifecycle.purge_tenant so this endpoint and the operator CLI
    # share one definition of "every table that holds tenant data".
    from .lifecycle import purge_tenant
    counts = purge_tenant(db, tenant)
    return {"deleted_tenant": slug, "deleted": counts}


# --- data-processing agreement (compliance record) -----------------------------------

def _dpa_state(tenant: Tenant) -> dict:
    return {
        "current_version": settings.dpa_version,
        "version": tenant.dpa_version or "",
        "accepted_at": tenant.dpa_accepted_at.isoformat() if tenant.dpa_accepted_at else None,
        "accepted_by": tenant.dpa_accepted_by or "",
        "accepted": bool(tenant.dpa_accepted_at) and (tenant.dpa_version == settings.dpa_version),
    }


@router.get("/tenant/dpa")
def get_dpa(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """The org's DPA acceptance record + the current version it should accept."""
    return _dpa_state(db.get(Tenant, current.tenant_id))


@router.post("/tenant/dpa")
def accept_dpa(body: DPAAccept, current: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    """Record that this admin accepted the data-processing agreement (compliance)."""
    tenant = db.get(Tenant, current.tenant_id)
    version = (body.version or settings.dpa_version).strip() or settings.dpa_version
    tenant.dpa_version = version
    tenant.dpa_accepted_at = _naive_utc()
    tenant.dpa_accepted_by = current.email
    db.commit()
    db.refresh(tenant)
    audit_log.record(db, current.tenant_id, current.email, "dpa.accept", detail={"version": version})
    return _dpa_state(tenant)


# --- per-tenant OIDC / SSO -----------------------------------------------------------

def _oidc_state(tenant_id: int, db: Session) -> dict:
    row = db.query(TenantOIDC).filter(TenantOIDC.tenant_id == tenant_id).first()
    if row is None:
        return {"configured": False, "enabled": False}
    return {
        "configured": True,
        "issuer": row.issuer,
        "client_id": row.client_id,
        "secret_set": bool(row.client_secret_encrypted),   # never return the secret
        "enabled": row.enabled,
        "auto_provision": row.auto_provision,
        "allowed_domain": row.allowed_domain,
    }


@router.get("/oidc")
def get_oidc(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """This org's SSO config (issuer/client_id/flags; the secret is never returned)."""
    return _oidc_state(current.tenant_id, db)


@router.put("/oidc")
def set_oidc(body: OIDCConfig, current: User = Depends(require_admin),
             db: Session = Depends(get_db)):
    """Configure OpenID Connect SSO for this org. Empty client_secret keeps the existing
    one. Fields left unset (None) are unchanged."""
    from .plans import require_feature
    require_feature(db.get(Tenant, current.tenant_id), "sso")
    row = db.query(TenantOIDC).filter(TenantOIDC.tenant_id == current.tenant_id).first()
    if row is None:
        row = TenantOIDC(tenant_id=current.tenant_id)
        db.add(row)
    row.issuer = body.issuer.strip() or row.issuer
    row.client_id = body.client_id.strip() or row.client_id
    if body.client_secret:
        row.client_secret_encrypted = crypto.seal_secret(
            crypto.dek_for(db, row.tenant_id), body.client_secret)
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.auto_provision is not None:
        row.auto_provision = body.auto_provision
    if body.allowed_domain is not None:
        row.allowed_domain = body.allowed_domain.strip().lower()
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "oidc.update",
                     detail={"enabled": row.enabled})
    return _oidc_state(current.tenant_id, db)


@router.delete("/oidc")
def delete_oidc(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.query(TenantOIDC).filter(TenantOIDC.tenant_id == current.tenant_id).first()
    if row is not None:
        db.delete(row)
        db.commit()
    audit_log.record(db, current.tenant_id, current.email, "oidc.delete")
    return {"configured": False, "enabled": False}


def _enabled_oidc(org: str, db: Session) -> tuple[Tenant, TenantOIDC]:
    tenant = db.query(Tenant).filter(Tenant.slug == org.strip().lower()).first()
    row = (db.query(TenantOIDC).filter(TenantOIDC.tenant_id == tenant.id).first()
           if tenant else None)
    if row is None or not row.enabled or not (row.issuer and row.client_id):
        raise HTTPException(status_code=404, detail="SSO is not configured for this organization")
    return tenant, row


@router.get("/auth/oidc/{org}/login")
def oidc_login(org: str, request: Request, db: Session = Depends(get_db)):
    """Begin the SSO auth-code flow: redirect the browser to the tenant's IdP."""
    tenant, row = _enabled_oidc(org, db)
    meta = oidc.discover(row.issuer)   # raises OIDCError -> 500-ish; acceptable for misconfig
    nonce = secrets.token_urlsafe(16)
    # Signed, self-expiring state — no server-side session store needed (multi-worker safe).
    state = create_token({"typ": "oidc_state", "org": tenant.slug, "nonce": nonce}, ttl=600)
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/api/auth/oidc/{tenant.slug}/callback"
    return RedirectResponse(oidc.authorize_url(meta, row.client_id, redirect_uri, state, nonce),
                            status_code=307)


@router.get("/auth/oidc/{org}/callback")
def oidc_callback(org: str, request: Request, code: str = "", state: str = "",
                  db: Session = Depends(get_db)):
    """IdP redirect target: validate state, exchange the code, validate the ID token,
    map/provision the user, and hand a Palivane session back to the console (URL fragment)."""
    try:
        payload = decode_token(state)
    except TokenError:
        raise HTTPException(status_code=400, detail="invalid or expired SSO state")
    if payload.get("typ") != "oidc_state" or payload.get("org") != org.strip().lower():
        raise HTTPException(status_code=400, detail="SSO state mismatch")

    tenant, row = _enabled_oidc(org, db)
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/api/auth/oidc/{tenant.slug}/callback"
    secret = crypto.unseal_secret(row.client_secret_encrypted, crypto.tenant_dek(tenant, db))
    try:
        meta = oidc.discover(row.issuer)
        tokens = oidc.exchange_code(meta, row.client_id, secret, code, redirect_uri)
        claims = oidc.validate_id_token(meta, row.issuer, row.client_id,
                                        tokens.get("id_token", ""), payload.get("nonce", ""))
    except oidc.OIDCError as e:
        raise HTTPException(status_code=401, detail=str(e))

    return _sso_complete(db, tenant, claims["email"], row.auto_provision,
                         row.allowed_domain, base)


def _sso_complete(db: Session, tenant: Tenant, email: str, auto_provision: bool,
                  allowed_domain: str, base: str) -> RedirectResponse:
    """Shared SSO tail (OIDC + SAML): enforce domain, map/provision the user, mint a
    session, and hand it to the console via URL fragment."""
    from .lifecycle import ensure_active
    ensure_active(db, tenant.id)
    email = (email or "").lower().strip()
    if allowed_domain and not email.endswith("@" + allowed_domain):
        raise HTTPException(status_code=403, detail="email domain not permitted for this org")

    user = (db.query(User)
            .filter(User.tenant_id == tenant.id, User.email == email).first())
    if user is None:
        if not auto_provision:
            raise HTTPException(status_code=403, detail="no account for this email, ask an admin")
        user = User(tenant_id=tenant.id, email=email,
                    password_hash=hash_password(secrets.token_urlsafe(32)), role="analyst")
        db.add(user)
        db.commit()
        db.refresh(user)
    elif not user.active:
        raise HTTPException(status_code=403, detail="account is disabled")

    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version})
    # Build the token-bearing redirect from the CONFIGURED public origin when set, not the
    # client Host header — otherwise a spoofed Host would redirect the session token to an
    # attacker domain (open-redirect / token exfil). Fall back to request-derived base.
    origin = settings.public_base_url or base
    # Hand the session to the SPA via URL fragment (not query — keeps it out of logs).
    return RedirectResponse(f"{origin}/#sso_token={token}", status_code=303)


# --- per-tenant SAML SSO -------------------------------------------------------------

def _saml_state(tenant_id: int, db: Session) -> dict:
    row = db.query(TenantSAML).filter(TenantSAML.tenant_id == tenant_id).first()
    if row is None:
        return {"configured": False, "enabled": False}
    return {
        "configured": True, "idp_entity_id": row.idp_entity_id, "idp_sso_url": row.idp_sso_url,
        "cert_set": bool(row.idp_x509_cert), "enabled": row.enabled,
        "auto_provision": row.auto_provision, "allowed_domain": row.allowed_domain,
    }


@router.get("/saml")
def get_saml(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    return _saml_state(current.tenant_id, db)


@router.put("/saml")
def set_saml(body: SAMLConfig, current: User = Depends(require_admin),
             db: Session = Depends(get_db)):
    """Configure SAML SSO for this org (we're the SP). The IdP cert is public, not a secret."""
    from .plans import require_feature
    require_feature(db.get(Tenant, current.tenant_id), "sso")
    row = db.query(TenantSAML).filter(TenantSAML.tenant_id == current.tenant_id).first()
    if row is None:
        row = TenantSAML(tenant_id=current.tenant_id)
        db.add(row)
    row.idp_entity_id = body.idp_entity_id.strip() or row.idp_entity_id
    row.idp_sso_url = body.idp_sso_url.strip() or row.idp_sso_url
    if body.idp_x509_cert:
        row.idp_x509_cert = body.idp_x509_cert.strip()
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.auto_provision is not None:
        row.auto_provision = body.auto_provision
    if body.allowed_domain is not None:
        row.allowed_domain = body.allowed_domain.strip().lower()
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "saml.update",
                     detail={"enabled": row.enabled})
    return _saml_state(current.tenant_id, db)


@router.delete("/saml")
def delete_saml(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.query(TenantSAML).filter(TenantSAML.tenant_id == current.tenant_id).first()
    if row is not None:
        db.delete(row)
        db.commit()
    audit_log.record(db, current.tenant_id, current.email, "saml.delete")
    return {"configured": False, "enabled": False}


def _enabled_saml(org: str, db: Session):
    tenant = db.query(Tenant).filter(Tenant.slug == org.strip().lower()).first()
    row = (db.query(TenantSAML).filter(TenantSAML.tenant_id == tenant.id).first()
           if tenant else None)
    if row is None or not row.enabled or not (row.idp_entity_id and row.idp_sso_url and row.idp_x509_cert):
        raise HTTPException(status_code=404, detail="SAML is not configured for this organization")
    return tenant, row


def _saml_req(request: Request, post_data: dict | None = None) -> dict:
    url = request.url
    host = url.hostname or ""
    if url.port and url.port not in (80, 443):
        host = f"{host}:{url.port}"
    return {
        "https": "on" if url.scheme == "https" else "off",
        "http_host": host,
        "script_name": url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


def _saml_sp(base: str, slug: str) -> tuple[str, str]:
    return f"{base}/api/auth/saml/{slug}/metadata", f"{base}/api/auth/saml/{slug}/acs"


@router.get("/auth/saml/{org}/login")
def saml_login(org: str, request: Request, db: Session = Depends(get_db)):
    tenant, cfg = _enabled_saml(org, db)
    base = str(request.base_url).rstrip("/")
    sp_entity, acs = _saml_sp(base, tenant.slug)
    try:
        url = saml.login_url(_saml_req(request), cfg, sp_entity, acs, relay_state=base)
    except saml.SAMLError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return RedirectResponse(url, status_code=302)


@router.post("/auth/saml/{org}/acs")
async def saml_acs(org: str, request: Request, db: Session = Depends(get_db)):
    tenant, cfg = _enabled_saml(org, db)
    base = str(request.base_url).rstrip("/")
    sp_entity, acs = _saml_sp(base, tenant.slug)
    form = await request.form()
    req = _saml_req(request, post_data={k: v for k, v in form.items()})
    try:
        result = saml.process_acs(req, cfg, sp_entity, acs)
    except saml.SAMLError as e:
        raise HTTPException(status_code=401, detail=str(e))
    return _sso_complete(db, tenant, result["email"], cfg.auto_provision, cfg.allowed_domain, base)


@router.get("/auth/saml/{org}/metadata")
def saml_metadata(org: str, request: Request, db: Session = Depends(get_db)):
    from fastapi.responses import Response as _Resp
    tenant, cfg = _enabled_saml(org, db)
    base = str(request.base_url).rstrip("/")
    sp_entity, acs = _saml_sp(base, tenant.slug)
    try:
        xml = saml.sp_metadata(cfg, sp_entity, acs)
    except saml.SAMLError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return _Resp(content=xml, media_type="application/xml")


@router.get("/auth/sso/{org}/login")
def sso_login(org: str, request: Request, db: Session = Depends(get_db)):
    """Unified SSO entry: redirect to whichever protocol the org has enabled."""
    base = str(request.base_url).rstrip("/")
    tenant = db.query(Tenant).filter(Tenant.slug == org.strip().lower()).first()
    if tenant:
        o = db.query(TenantOIDC).filter(TenantOIDC.tenant_id == tenant.id).first()
        if o and o.enabled:
            return RedirectResponse(f"{base}/api/auth/oidc/{tenant.slug}/login", status_code=307)
        s = db.query(TenantSAML).filter(TenantSAML.tenant_id == tenant.id).first()
        if s and s.enabled:
            return RedirectResponse(f"{base}/api/auth/saml/{tenant.slug}/login", status_code=307)
    raise HTTPException(status_code=404, detail="SSO is not configured for this organization")
