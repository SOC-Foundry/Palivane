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
from .crypto import decrypt, encrypt
from .database import get_db
from .models import (
    ApiKey, AuditLog, EnrollmentToken, Finding, GatewayUsage, LoginAttempt, Tenant,
    TenantOIDC, TenantSAML, TenantUpstream, User,
)
from .schemas import (
    ApiKeyCreate, EnrollmentTokenCreate, EnrollRequest, LoginRequest, MFACode, MFAVerify,
    DPAAccept, OIDCConfig, SAMLConfig, SignupRequest, TenantDelete, TenantUpdate, UpstreamConfig,
    UserCreate, UserUpdate,
)
from .upstreams import PROVIDERS, resolve as resolve_upstream
from .security import (
    DUMMY_PASSWORD_HASH,
    TokenError,
    create_token,
    decode_token,
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
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    if int(payload.get("tv", 0)) != user.token_version:
        raise HTTPException(status_code=401, detail="session revoked — please sign in again")
    return user


def require_admin(current: User = Depends(get_current_user)) -> User:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return current


@router.post("/auth/signup")
def signup(body: SignupRequest, db: Session = Depends(get_db)):
    """Self-serve onboarding: create a new org (tenant) + its first admin, and log in.

    The first user of a new tenant is its admin; they then invite analysts via /api/users
    and configure the capture planes. Disabled when WARDEN_ALLOW_SIGNUP=false."""
    if not settings.allow_signup:
        raise HTTPException(status_code=403, detail="self-serve signup is disabled")
    slug = _unique_slug(db, _slugify(body.slug or body.org_name))
    tenant = Tenant(slug=slug, name=body.org_name.strip() or slug)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    user = User(tenant_id=tenant.id, email=body.email.lower().strip(),
                password_hash=hash_password(body.password), role="admin")
    db.add(user)
    db.commit()
    db.refresh(user)
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
                            detail="too many failed attempts — try again later")

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
                            detail="multiple organizations use this email — specify your org")
    if not user or not ok:
        db.add(LoginAttempt(email=email, ip=ip))
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")

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
        raise HTTPException(status_code=429, detail="too many attempts — try again later")

    ok = totp.verify(decrypt(user.mfa_secret), body.code)
    if not ok:
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
def me(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, current.tenant_id)
    return {"user": current.to_dict(), "tenant": tenant.to_dict() if tenant else None}


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
    user = User(
        tenant_id=current.tenant_id, email=email,
        password_hash=hash_password(body.password), role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit_log.record(db, current.tenant_id, current.email, "user.create",
                     target=email, detail={"role": body.role})
    return user.to_dict()


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
def extension_token(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Mint a per-user, tenant-scoped capture key for the browser extension (self-serve /
    BYOD sign-in via the console). Any authenticated user can bind their own extension;
    attributed to their email for per-user findings, and revocable in the console like any
    API key. The console's /extension-connect page calls this after login/SSO and hands the
    token back to the extension via the OAuth redirect."""
    token, prefix, token_hash = generate_api_key()
    key = ApiKey(tenant_id=current.tenant_id, label="browser-extension",
                 actor=current.email, prefix=prefix, token_hash=token_hash)
    db.add(key)
    db.commit()
    db.refresh(key)
    audit_log.record(db, current.tenant_id, current.email, "extension.connect",
                     target=current.email)
    return {"token": token, "actor": current.email, "tenant": current.tenant_id}


@router.post("/apikeys")
def create_api_key(body: ApiKeyCreate, current: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    """Mint a long-lived API key for a machine client (gateway/SIEM). The plaintext is
    returned ONCE — only its hash is stored."""
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
    if et.max_uses is not None and et.uses >= et.max_uses:
        raise HTTPException(status_code=401, detail="enrollment token exhausted")

    token, prefix, token_hash = generate_api_key()
    key = ApiKey(tenant_id=et.tenant_id, label=f"device:{body.device}", actor=body.device,
                 prefix=prefix, token_hash=token_hash)
    et.uses = (et.uses or 0) + 1
    db.add(key)
    db.commit()
    audit_log.record(db, et.tenant_id, body.device, "device.enroll", target=body.device)
    return {"token": token, "actor": body.device, "base_url_hint": "/v1"}


# --- per-tenant upstream provider config (gateway billing isolation) -----------------

def _upstream_state(provider: str, tenant_id: int, db: Session) -> dict:
    row = (db.query(TenantUpstream)
           .filter(TenantUpstream.tenant_id == tenant_id, TenantUpstream.provider == provider)
           .first())
    eff_base, eff_key = resolve_upstream(provider, tenant_id, db)
    return {
        "provider": provider,
        "base_url": row.base_url if row else "",
        "key_set": bool(row and row.key_encrypted),   # never return the key itself
        "effective": "tenant" if row and (row.base_url or row.key_encrypted) else "global",
        "forwards": bool(eff_base if provider == "openai" else eff_key),
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
        from .netguard import is_safe_url
        if not is_safe_url(base):
            raise HTTPException(status_code=400,
                                detail="base_url must be an https(s) URL to a public host "
                                       "(private/loopback/metadata addresses are blocked)")
    if row is None:
        row = TenantUpstream(tenant_id=current.tenant_id, provider=provider)
        db.add(row)
    row.base_url = base
    if body.key:
        row.key_encrypted = encrypt(body.key)
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


# --- tenant settings & lifecycle (data control) --------------------------------------

_JUDGE = {"on": True, "off": False, "inherit": None}


@router.patch("/tenant")
def update_tenant(body: TenantUpdate, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Org settings: display name, Claude-judge consent, and findings retention."""
    tenant = db.get(Tenant, current.tenant_id)
    if body.name is not None:
        tenant.name = body.name.strip() or tenant.name
    if body.judge is not None:
        tenant.judge_enabled = _JUDGE[body.judge]
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
        tenant.alert_webhook = body.alert_webhook.strip()
    if body.alert_min_severity is not None:
        if body.alert_min_severity not in ("low", "suspicious", "high", "critical"):
            raise HTTPException(status_code=400, detail="invalid alert_min_severity")
        tenant.alert_min_severity = body.alert_min_severity
    if body.alert_digest is not None:
        if body.alert_digest not in ("off", "hourly", "daily"):
            raise HTTPException(status_code=400, detail="invalid alert_digest")
        tenant.alert_digest = body.alert_digest
    # SIEM forwarding (URL is SSRF-guarded at send time, like the alert webhook).
    if body.siem_url is not None:
        tenant.siem_url = body.siem_url.strip()
    if body.siem_token is not None:
        tenant.siem_token = body.siem_token.strip()
    if body.siem_min_severity is not None:
        if body.siem_min_severity not in ("low", "suspicious", "high", "critical"):
            raise HTTPException(status_code=400, detail="invalid siem_min_severity")
        tenant.siem_min_severity = body.siem_min_severity
    if body.siem_format is not None:
        if body.siem_format not in ("json", "splunk_hec", "cef"):
            raise HTTPException(status_code=400, detail="invalid siem_format")
        tenant.siem_format = body.siem_format
    if body.gateway_enforce is not None:
        tenant.gateway_enforce = _JUDGE[body.gateway_enforce]  # same tri-state mapping
    for sev_field in ("gateway_block_severity", "mcp_block_severity"):
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
    changed = body.model_dump(exclude_none=True)
    audit_log.record(db, current.tenant_id, current.email, "tenant.update", detail=changed)
    return tenant.to_dict()


@router.delete("/tenant")
def delete_tenant(body: TenantDelete, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """Delete this organization and ALL its data (GDPR "delete my org"). Irreversible —
    the caller must pass the tenant slug as `confirm`."""
    tenant = db.get(Tenant, current.tenant_id)
    if body.confirm != tenant.slug:
        raise HTTPException(status_code=400,
                            detail=f"to confirm deletion, pass confirm=\"{tenant.slug}\"")
    tid = tenant.id
    slug = tenant.slug
    # Delete every table that holds this tenant's data — a partial delete isn't a delete.
    counts = {
        "findings": db.query(Finding).filter(Finding.tenant_id == tid).delete(),
        "users": db.query(User).filter(User.tenant_id == tid).delete(),
        "api_keys": db.query(ApiKey).filter(ApiKey.tenant_id == tid).delete(),
        "enrollment_tokens": db.query(EnrollmentToken).filter(EnrollmentToken.tenant_id == tid).delete(),
        "upstreams": db.query(TenantUpstream).filter(TenantUpstream.tenant_id == tid).delete(),
        "audit_log": db.query(AuditLog).filter(AuditLog.tenant_id == tid).delete(),
        "usage": db.query(GatewayUsage).filter(GatewayUsage.tenant_id == tid).delete(),
        "oidc": db.query(TenantOIDC).filter(TenantOIDC.tenant_id == tid).delete(),
        "saml": db.query(TenantSAML).filter(TenantSAML.tenant_id == tid).delete(),
    }
    db.delete(tenant)
    db.commit()
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
    row = db.query(TenantOIDC).filter(TenantOIDC.tenant_id == current.tenant_id).first()
    if row is None:
        row = TenantOIDC(tenant_id=current.tenant_id)
        db.add(row)
    row.issuer = body.issuer.strip() or row.issuer
    row.client_id = body.client_id.strip() or row.client_id
    if body.client_secret:
        row.client_secret_encrypted = encrypt(body.client_secret)
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
    map/provision the user, and hand a Warden session back to the console (URL fragment)."""
    try:
        payload = decode_token(state)
    except TokenError:
        raise HTTPException(status_code=400, detail="invalid or expired SSO state")
    if payload.get("typ") != "oidc_state" or payload.get("org") != org.strip().lower():
        raise HTTPException(status_code=400, detail="SSO state mismatch")

    tenant, row = _enabled_oidc(org, db)
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/api/auth/oidc/{tenant.slug}/callback"
    secret = decrypt(row.client_secret_encrypted)
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
    email = (email or "").lower().strip()
    if allowed_domain and not email.endswith("@" + allowed_domain):
        raise HTTPException(status_code=403, detail="email domain not permitted for this org")

    user = (db.query(User)
            .filter(User.tenant_id == tenant.id, User.email == email).first())
    if user is None:
        if not auto_provision:
            raise HTTPException(status_code=403, detail="no account for this email — ask an admin")
        user = User(tenant_id=tenant.id, email=email,
                    password_hash=hash_password(secrets.token_urlsafe(32)), role="analyst")
        db.add(user)
        db.commit()
        db.refresh(user)
    elif not user.active:
        raise HTTPException(status_code=403, detail="account is disabled")

    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version})
    # Hand the session to the SPA via URL fragment (not query — keeps it out of logs).
    return RedirectResponse(f"{base}/#sso_token={token}", status_code=303)


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
