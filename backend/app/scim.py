"""SCIM 2.0 user provisioning (RFC 7643/7644) — the IdP-driven lifecycle plane.

Okta / Entra ID / OneLogin push joiners, movers, and leavers here, so the org's directory
is the source of truth: a person removed from the IdP is deactivated in Palivane within
the IdP's sync interval instead of whenever someone remembers. Users resource only —
Palivane's authorization model is two roles, so Groups have nothing to map onto (role
stays a console decision; SCIM-created users arrive as analysts).

Auth: a per-tenant bearer token (`scim_…`), minted by an admin in the console (one active
token per org; minting again rotates it). Stored as a SHA-256 hash — the plaintext is
shown once, like API keys. The SCIM base URL is /scim/v2, at the API origin.

Semantics worth naming:
  - DELETE deactivates (soft): the audit trail and the user's findings history must
    survive offboarding — SCIM's own spec permits it and every major IdP handles it.
  - Deactivation bumps token_version, killing the user's live sessions immediately.
  - The last active admin cannot be deactivated over SCIM: a mis-scoped IdP push must
    not be able to lock an org out of its own console.
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .database import bind_tenant, get_db
from .models import Tenant, User
from .security import hash_password

router = APIRouter(prefix="/scim/v2", tags=["scim"])

_SCIM_CT = "application/scim+json"
_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _err(status: int, detail: str, scim_type: str = "") -> JSONResponse:
    body = {"schemas": [_ERROR_SCHEMA], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(status_code=status, content=body, media_type=_SCIM_CT)


class ScimError(HTTPException):
    def __init__(self, status: int, detail: str, scim_type: str = ""):
        super().__init__(status_code=status, detail=detail)
        self.scim_type = scim_type


def scim_tenant(authorization: str = Header(default=""),
                db: Session = Depends(get_db)) -> Tenant:
    """Resolve the bearer token to its tenant (and bind RLS). 401 on anything else —
    SCIM clients treat 401 as 'reauthorize', which is the correct prompt for a rotated
    token."""
    token = authorization.removeprefix("Bearer ").strip()
    if not token.startswith("scim_"):
        raise HTTPException(status_code=401, detail="SCIM bearer token required")
    h = sha256(token.encode()).hexdigest()
    t = db.query(Tenant).filter(Tenant.scim_token_hash == h).first()
    if t is None:
        raise HTTPException(status_code=401, detail="unknown SCIM token")
    bind_tenant(db, t.id)
    return t


def mint_token(db: Session, tenant: Tenant) -> str:
    """A fresh SCIM token for the org (rotates any prior one). Caller audits + commits."""
    token = "scim_" + secrets.token_urlsafe(32)
    tenant.scim_token_hash = sha256(token.encode()).hexdigest()
    return token


def _resource(u: User) -> dict:
    return {
        "schemas": [_USER_SCHEMA],
        "id": str(u.id),
        "userName": u.email,
        "active": bool(u.active),
        "emails": [{"value": u.email, "primary": True}],
        "meta": {"resourceType": "User",
                 "created": u.created_at.isoformat() + "Z" if u.created_at else None},
    }


def _active_admins(db: Session, tenant_id: int) -> int:
    return (db.query(User).filter(User.tenant_id == tenant_id, User.role == "admin",
                                  User.active.is_(True)).count())


def _get_user(db: Session, tenant: Tenant, user_id: str) -> User:
    row = None
    if user_id.isdigit():
        row = (db.query(User).filter(User.tenant_id == tenant.id,
                                     User.id == int(user_id)).first())
    if row is None:
        raise ScimError(404, f"User {user_id} not found")
    return row


def _audit(db, tenant, action, target, detail=None):
    from . import audit_log
    audit_log.record(db, tenant.id, "scim", action, target=target, detail=detail or {})


@router.get("/ServiceProviderConfig")
def service_provider_config(tenant: Tenant = Depends(scim_tenant)):
    return JSONResponse(media_type=_SCIM_CT, content={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken", "name": "Bearer token",
            "description": "Per-org SCIM token minted in the Palivane console"}],
    })


@router.get("/ResourceTypes")
def resource_types(tenant: Tenant = Depends(scim_tenant)):
    return JSONResponse(media_type=_SCIM_CT, content={
        "schemas": [_LIST_SCHEMA], "totalResults": 1, "startIndex": 1, "itemsPerPage": 1,
        "Resources": [{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User", "name": "User", "endpoint": "/Users", "schema": _USER_SCHEMA}],
    })


@router.get("/Users")
def list_users(tenant: Tenant = Depends(scim_tenant), db: Session = Depends(get_db),
               filter: str = Query(default=""), startIndex: int = Query(default=1, ge=1),
               count: int = Query(default=100, ge=0, le=200)):
    """List/search. The one filter every IdP actually sends is
    `userName eq "someone@org.com"` (the pre-create existence probe) — support exactly
    that; anything else is a 501 rather than silently-wrong results."""
    q = db.query(User).filter(User.tenant_id == tenant.id)
    if filter:
        import re
        m = re.fullmatch(r'\s*userName\s+eq\s+"([^"]+)"\s*', filter, re.IGNORECASE)
        if not m:
            return _err(501, f"unsupported filter: {filter}", "invalidFilter")
        q = q.filter(User.email == m.group(1).lower().strip())
    total = q.count()
    rows = q.order_by(User.id).offset(startIndex - 1).limit(count).all()
    return JSONResponse(media_type=_SCIM_CT, content={
        "schemas": [_LIST_SCHEMA], "totalResults": total,
        "startIndex": startIndex, "itemsPerPage": len(rows),
        "Resources": [_resource(u) for u in rows],
    })


@router.post("/Users", status_code=201)
def create_user(body: dict, tenant: Tenant = Depends(scim_tenant),
                db: Session = Depends(get_db)):
    email = str(body.get("userName") or "").lower().strip()
    if not email or "@" not in email:
        return _err(400, "userName must be an email address", "invalidValue")
    if db.query(User).filter(User.tenant_id == tenant.id, User.email == email).first():
        return _err(409, f"user {email} already exists", "uniqueness")
    u = User(tenant_id=tenant.id, email=email, role="analyst",
             active=bool(body.get("active", True)),
             # Random unusable password: SCIM-provisioned users sign in via SSO (or set
             # one through the reset flow) — provisioning must never mint a credential.
             password_hash=hash_password(secrets.token_urlsafe(32)))
    db.add(u)
    db.commit()
    db.refresh(u)
    _audit(db, tenant, "scim.user_created", email)
    return JSONResponse(status_code=201, media_type=_SCIM_CT, content=_resource(u))


@router.get("/Users/{user_id}")
def get_user(user_id: str, tenant: Tenant = Depends(scim_tenant),
             db: Session = Depends(get_db)):
    try:
        return JSONResponse(media_type=_SCIM_CT,
                            content=_resource(_get_user(db, tenant, user_id)))
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)


def _apply_active(db, tenant, u: User, active: bool) -> JSONResponse | None:
    if u.active and not active:
        if u.role == "admin" and _active_admins(db, tenant.id) <= 1:
            return _err(409, "cannot deactivate the last active admin", "mutability")
        u.active = False
        u.token_version = (u.token_version or 0) + 1     # log out everywhere, now
        _audit(db, tenant, "scim.user_deactivated", u.email)
    elif not u.active and active:
        u.active = True
        _audit(db, tenant, "scim.user_reactivated", u.email)
    return None


@router.put("/Users/{user_id}")
def replace_user(user_id: str, body: dict, tenant: Tenant = Depends(scim_tenant),
                 db: Session = Depends(get_db)):
    try:
        u = _get_user(db, tenant, user_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    email = str(body.get("userName") or "").lower().strip()
    if email and email != u.email:
        if db.query(User).filter(User.tenant_id == tenant.id, User.email == email).first():
            return _err(409, f"user {email} already exists", "uniqueness")
        _audit(db, tenant, "scim.user_renamed", u.email, {"to": email})
        u.email = email
    if "active" in body:
        blocked = _apply_active(db, tenant, u, bool(body.get("active")))
        if blocked is not None:
            return blocked
    db.commit()
    db.refresh(u)
    return JSONResponse(media_type=_SCIM_CT, content=_resource(u))


@router.patch("/Users/{user_id}")
def patch_user(user_id: str, body: dict, tenant: Tenant = Depends(scim_tenant),
               db: Session = Depends(get_db)):
    """PatchOp: the ops IdPs actually send — replace on `active` (Okta/Entra deactivate)
    and on `userName`. Unknown paths are ignored per RFC 7644's leniency for
    non-supported attributes rather than failing the whole sync."""
    try:
        u = _get_user(db, tenant, user_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    for op in (body.get("Operations") or []):
        if str(op.get("op", "")).lower() != "replace":
            continue
        path = str(op.get("path") or "").strip()
        value = op.get("value")
        # Entra sends path-less replace with a value object: {"active": false, ...}
        updates = value if not path and isinstance(value, dict) else {path: value}
        for key, val in (updates or {}).items():
            if key == "active":
                truthy = val if isinstance(val, bool) else str(val).lower() == "true"
                blocked = _apply_active(db, tenant, u, truthy)
                if blocked is not None:
                    return blocked
            elif key == "userName" and val:
                email = str(val).lower().strip()
                if email != u.email:
                    if db.query(User).filter(User.tenant_id == tenant.id,
                                             User.email == email).first():
                        return _err(409, f"user {email} already exists", "uniqueness")
                    _audit(db, tenant, "scim.user_renamed", u.email, {"to": email})
                    u.email = email
    db.commit()
    db.refresh(u)
    return JSONResponse(media_type=_SCIM_CT, content=_resource(u))


@router.delete("/Users/{user_id}", status_code=204)
def delete_user(user_id: str, tenant: Tenant = Depends(scim_tenant),
                db: Session = Depends(get_db)):
    """Soft delete: deactivate. Findings history and the audit trail must survive
    offboarding; every major IdP treats a 204 as done."""
    try:
        u = _get_user(db, tenant, user_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    blocked = _apply_active(db, tenant, u, False)
    if blocked is not None:
        return blocked
    db.commit()
    return Response(status_code=204)
