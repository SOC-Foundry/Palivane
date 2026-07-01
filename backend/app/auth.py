"""Authentication dependencies and the /api/auth + /api/users routes.

`get_current_user` turns a Bearer token into the authenticated `User` (loaded fresh
from the DB so deactivation/role changes take effect immediately). `require_admin`
gates user-management routes. Tenant isolation is enforced by callers scoping their
queries to `current_user.tenant_id`.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .crypto import encrypt
from .database import get_db
from .models import ApiKey, Finding, LoginAttempt, Tenant, TenantUpstream, User
from .schemas import (
    ApiKeyCreate, LoginRequest, SignupRequest, TenantDelete, TenantUpdate,
    UpstreamConfig, UserCreate, UserUpdate,
)
from .upstreams import PROVIDERS, resolve as resolve_upstream
from .security import (
    TokenError,
    create_token,
    decode_token,
    generate_api_key,
    hash_password,
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
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id, "role": user.role})
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
    placeholder = "pbkdf2_sha256$200000$" + "00" * 16 + "$" + "00" * 32
    ok = verify_password(body.password, user.password_hash if user else placeholder)
    if ambiguous:
        raise HTTPException(status_code=409,
                            detail="multiple organizations use this email — specify your org")
    if not user or not ok:
        db.add(LoginAttempt(email=email, ip=ip))
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")

    # Successful login clears this email's recent failures.
    db.query(LoginAttempt).filter(LoginAttempt.email == email).delete()
    db.commit()
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "user": user.to_dict()}


@router.get("/auth/me")
def me(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, current.tenant_id)
    return {"user": current.to_dict(), "tenant": tenant.to_dict() if tenant else None}


@router.get("/users")
def list_users(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(User).filter(User.tenant_id == current.tenant_id).all()
    return {"users": [u.to_dict() for u in rows]}


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
    return user.to_dict()


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
    return {"id": key_id, "active": False}


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
    if row is None:
        row = TenantUpstream(tenant_id=current.tenant_id, provider=provider)
        db.add(row)
    row.base_url = body.base_url.strip()
    if body.key:
        row.key_encrypted = encrypt(body.key)
    db.commit()
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
    db.commit()
    db.refresh(tenant)
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
    counts = {
        "findings": db.query(Finding).filter(Finding.tenant_id == tid).delete(),
        "users": db.query(User).filter(User.tenant_id == tid).delete(),
        "api_keys": db.query(ApiKey).filter(ApiKey.tenant_id == tid).delete(),
        "upstreams": db.query(TenantUpstream).filter(TenantUpstream.tenant_id == tid).delete(),
    }
    db.delete(tenant)
    db.commit()
    return {"deleted_tenant": tenant.slug, "deleted": counts}
