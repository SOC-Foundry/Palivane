"""Authentication dependencies and the /api/auth + /api/users routes.

`get_current_user` turns a Bearer token into the authenticated `User` (loaded fresh
from the DB so deactivation/role changes take effect immediately). `require_admin`
gates user-management routes. Tenant isolation is enforced by callers scoping their
queries to `current_user.tenant_id`.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import ApiKey, Tenant, User
from .schemas import ApiKeyCreate, LoginRequest, SignupRequest, UserCreate
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


@router.post("/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = (
        db.query(User)
        .filter(User.email == body.email.lower().strip(), User.active.is_(True))
        .first()
    )
    # Verify even on miss to keep timing uniform; never reveal which factor failed.
    placeholder = "pbkdf2_sha256$200000$" + "00" * 16 + "$" + "00" * 32
    ok = verify_password(body.password, user.password_hash if user else placeholder)
    if not user or not ok:
        raise HTTPException(status_code=401, detail="invalid credentials")
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
