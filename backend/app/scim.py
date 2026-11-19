"""SCIM 2.0 provisioning (RFC 7643/7644) — the IdP-driven lifecycle plane.

Okta / Entra ID / OneLogin push joiners, movers, and leavers here, so the org's directory
is the source of truth: a person removed from the IdP is deactivated in Palivane within
the IdP's sync interval instead of whenever someone remembers. Users arrive as members.
Groups — the Groups resource, or a `groups` attribute on the User — map to a console
role and a Discovery team through the mappings an admin saved. Unmapped groups do not
change a role that was set in the console.

Auth: a per-tenant bearer token (`scim_…`), minted by an admin in the console (one active
token per org; minting again rotates it). Stored as a SHA-256 hash — the plaintext is
shown once, like API keys. The SCIM base URL is /scim/v2, at the API origin.

Semantics worth naming:
  - DELETE deactivates (soft): the audit trail and the user's findings history must
    survive offboarding — SCIM's own spec permits it and every major IdP handles it.
  - Deactivation bumps token_version, killing the user's live sessions immediately.
  - The last active admin cannot be deactivated over SCIM: a mis-scoped IdP push must
    not be able to lock an org out of its own console.
  - Admins cannot be renamed or reactivated over SCIM: a provisioning-scoped credential
    (leaked or mis-scoped) must not be able to hijack a privileged account's login identity
    by changing its email, or bring back an admin the console offboarded.     Admin lifecycle
    is a console decision. A mapped group may still change an admin's role, except the
    last active admin, who is never removed this way.
"""

from __future__ import annotations

import secrets
from hashlib import sha256

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .database import bind_tenant, get_db
from .models import ScimGroup, ScimGroupMember, Tenant, User
from .security import hash_password

router = APIRouter(prefix="/scim/v2", tags=["scim"])

_SCIM_CT = "application/scim+json"
_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
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
    from .lifecycle import ensure_active
    ensure_active(db, t.id)          # a suspended org's directory can't provision into it
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


def _apply_user_groups(db, user: User, groups: list[str] | None, op: str = "replace") -> None:
    """Apply a SCIM user `groups` attribute. None means the payload didn't mention groups."""
    if groups is None:
        return
    from .groups import collapse_groups, set_group_source
    op = (op or "replace").lower()
    if op == "add":
        current = collapse_groups((user.group_sources or {}).get("scim_attr"))
        groups = current + list(groups)
    elif op == "remove" and groups:
        current = collapse_groups((user.group_sources or {}).get("scim_attr"))
        drop = {g.lower() for g in groups}
        groups = [g for g in current if g.lower() not in drop]
    elif op == "remove":
        groups = []
    set_group_source(db, user, "scim_attr", groups, actor="scim")


def _audit(db, tenant, action, target, detail=None):
    """Queue an audit entry for after the request commits (_commit). audit_log.record
    commits, so writing it mid-request committed the operations before it too: a PatchOp
    whose later operation was refused still applied its earlier ones."""
    from . import audit_log
    _after(db, lambda: audit_log.record(db, tenant.id, "scim", action, target=target,
                                        detail=detail or {}))


def _after(db, fn) -> None:
    """Run `fn` once this request's changes are committed; dropped if they are rolled back."""
    db.info.setdefault("scim_after", []).append(fn)


def _commit(db) -> None:
    """Commit the request's changes, then run what was queued for after (audit, mail)."""
    db.commit()
    for fn in db.info.pop("scim_after", []):
        fn()


def _refuse(db, resp: JSONResponse) -> JSONResponse:
    """Refuse the whole request: nothing it changed is kept, nothing queued runs."""
    db.rollback()
    db.info.pop("scim_after", None)
    return resp


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
        "schemas": [_LIST_SCHEMA], "totalResults": 2, "startIndex": 1, "itemsPerPage": 2,
        "Resources": [
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
             "id": "User", "name": "User", "endpoint": "/Users", "schema": _USER_SCHEMA},
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
             "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": _GROUP_SCHEMA},
        ],
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
    from .auth import check_seat
    try:
        check_seat(db, tenant.id)
    except HTTPException as e:
        return _err(403, str(e.detail), "")
    u = User(tenant_id=tenant.id, email=email, role="member",
             active=bool(body.get("active", True)),
             # Random unusable password: SCIM-provisioned users sign in via SSO (or set
             # one through the reset flow) — provisioning must never mint a credential.
             password_hash=hash_password(secrets.token_urlsafe(32)))
    db.add(u)
    from .groups import groups_from_scim_user
    _apply_user_groups(db, u, groups_from_scim_user(body))
    _audit(db, tenant, "scim.user_created", email)
    _commit(db)
    db.refresh(u)
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
        from .auth import lock_admin_changes
        lock_admin_changes(db, tenant.id)
        if u.role == "admin" and _active_admins(db, tenant.id) <= 1:
            return _err(409, "cannot deactivate the last active admin", "mutability")
        u.active = False
        u.token_version = (u.token_version or 0) + 1     # log out everywhere, now
        from .auth import revoke_user_keys                # and their API keys / OAuth grants
        revoke_user_keys(db, u)
        if u.role == "admin":                             # re-count after the write (SQLite)
            db.flush()
            if _active_admins(db, tenant.id) < 1:
                return _err(409, "cannot deactivate the last active admin", "mutability")
        _audit(db, tenant, "scim.user_deactivated", u.email)
    elif not u.active and active:
        if u.role == "admin":
            # Same rule as renames: restoring a privileged login is a console decision. An
            # admin offboarded in the console must not come back on a provisioning push.
            return _err(403, "cannot reactivate an admin over SCIM; manage admins in the "
                             "console", "mutability")
        u.active = True
        _audit(db, tenant, "scim.user_reactivated", u.email)
    return None


def _apply_rename(db, tenant, u: User, raw_email: str) -> JSONResponse | None:
    """Apply a userName (email) change, or return the SCIM error response that blocks it.

    Admins are console-managed: a provisioning-scoped credential must not be able to rename
    a privileged account, which would hand identity takeover to a leaked or mis-scoped IdP
    token (rename the admin's email away, then re-point a controlled account at it). A
    collision with an existing member is a SCIM uniqueness error, per RFC 7644."""
    email = raw_email.lower().strip()
    if not email or email == u.email:
        return None
    if u.role == "admin":
        return _err(403, "cannot rename an admin over SCIM; manage admins in the console",
                    "mutability")
    if db.query(User).filter(User.tenant_id == tenant.id, User.email == email).first():
        return _err(409, f"user {email} already exists", "uniqueness")
    _audit(db, tenant, "scim.user_renamed", u.email, {"to": email})
    old = u.email
    u.email = email
    # The login identity changed, so whatever was signed in under the old one re-authenticates.
    # And tell the old address: a leaked SCIM token can point an analyst's account at an
    # address it controls and then take it over with a password reset, and the person who
    # would notice is the one whose address was just removed. (No-op when email is off.)
    u.token_version = (u.token_version or 0) + 1
    from .auth import repoint_capture_keys, revoke_oauth_grants
    revoke_oauth_grants(db, u)
    repoint_capture_keys(db, tenant.id, old, email)
    from . import email as email_mod
    _after(db, lambda: email_mod.send(
        old, "Your Palivane sign-in address was changed",
        f"Your organization's identity provider changed the sign-in address of your Palivane "
        f"account (organization \"{tenant.slug}\") from {old} to {email}, and signed you out.\n\n"
        "If you expected this, there is nothing to do. If not, tell your Palivane admin now: "
        "the new address can reset the account's password."))
    return None


@router.put("/Users/{user_id}")
def replace_user(user_id: str, body: dict, tenant: Tenant = Depends(scim_tenant),
                 db: Session = Depends(get_db)):
    try:
        u = _get_user(db, tenant, user_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    blocked = _apply_rename(db, tenant, u, str(body.get("userName") or ""))
    if blocked is not None:
        return _refuse(db, blocked)
    if "active" in body:
        blocked = _apply_active(db, tenant, u, bool(body.get("active")))
        if blocked is not None:
            return _refuse(db, blocked)
    from .groups import groups_from_scim_user
    _apply_user_groups(db, u, groups_from_scim_user(body))
    _commit(db)
    db.refresh(u)
    return JSONResponse(media_type=_SCIM_CT, content=_resource(u))


@router.patch("/Users/{user_id}")
def patch_user(user_id: str, body: dict, tenant: Tenant = Depends(scim_tenant),
               db: Session = Depends(get_db)):
    """PatchOp: the ops IdPs actually send — replace on `active` (Okta/Entra deactivate)
    and on `userName`, plus add/remove/replace on `groups`. Unknown paths are ignored
    per RFC 7644's leniency for non-supported attributes rather than failing the sync."""
    try:
        u = _get_user(db, tenant, user_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    for op in (body.get("Operations") or []):
        name = str(op.get("op", "")).lower()
        path = str(op.get("path") or "").strip()
        groups_path = path.lower() == "groups" or path.lower().endswith(":groups")
        if name != "replace" and not groups_path:
            continue
        value = op.get("value")
        # Entra sends path-less replace with a value object: {"active": false, ...}
        updates = value if not path and isinstance(value, dict) else {path: value}
        for key, val in (updates or {}).items():
            if key == "active":
                truthy = val if isinstance(val, bool) else str(val).lower() == "true"
                blocked = _apply_active(db, tenant, u, truthy)
                if blocked is not None:
                    return _refuse(db, blocked)
            elif key == "userName" and val:
                blocked = _apply_rename(db, tenant, u, str(val))
                if blocked is not None:
                    return _refuse(db, blocked)
            elif key == "groups" or key.lower().endswith(":groups"):
                from .groups import collapse_groups
                _apply_user_groups(db, u, collapse_groups(val), op=str(op.get("op", "replace")))
    _commit(db)
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
        return _refuse(db, blocked)
    _commit(db)
    return Response(status_code=204)


# --- Groups (Okta / Entra group push) ------------------------------------------------


def _group_resource(db: Session, group: ScimGroup) -> dict:
    members = (db.query(ScimGroupMember, User)
                 .join(User, User.id == ScimGroupMember.user_id)
                 .filter(ScimGroupMember.group_id == group.id)
                 .all())
    return {
        "schemas": [_GROUP_SCHEMA],
        "id": str(group.id),
        "displayName": group.display_name,
        "externalId": group.external_id or None,
        "members": [{"value": str(user.id), "display": user.email} for _, user in members],
        "meta": {"resourceType": "Group"},
    }


def _get_group(db: Session, tenant: Tenant, group_id: str) -> ScimGroup:
    row = None
    if str(group_id).isdigit():
        row = (db.query(ScimGroup)
                 .filter(ScimGroup.tenant_id == tenant.id, ScimGroup.id == int(group_id))
                 .first())
    if row is None:
        raise ScimError(404, f"Group {group_id} not found")
    return row


def _member_user(db: Session, tenant: Tenant, value) -> User | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        row = (db.query(User)
                 .filter(User.tenant_id == tenant.id, User.id == int(text))
                 .first())
        if row is not None:
            return row
    return (db.query(User)
              .filter(User.tenant_id == tenant.id, User.email == text.lower())
              .first())


def _member_values(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _recompute_users(db, users: list[User]) -> None:
    from .groups import apply_group_grants
    seen = set()
    for user in users:
        if user is None or user.id in seen:
            continue
        seen.add(user.id)
        apply_group_grants(db, user, actor="scim")


def _set_members(db, tenant: Tenant, group: ScimGroup, values) -> JSONResponse | None:
    """Replace the group's members with `values` (SCIM member objects or ids)."""
    wanted: list[User] = []
    for item in _member_values(values):
        raw = item.get("value") if isinstance(item, dict) else item
        user = _member_user(db, tenant, raw)
        if user is None:
            return _err(400, f"member {raw} not found", "invalidValue")
        wanted.append(user)
    current = {m.user_id: m for m in
               db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).all()}
    keep = {u.id for u in wanted}
    affected = []
    for uid, member in current.items():
        if uid not in keep:
            user = db.get(User, uid)
            db.delete(member)
            affected.append(user)
    for user in wanted:
        if user.id not in current:
            db.add(ScimGroupMember(tenant_id=tenant.id, group_id=group.id, user_id=user.id))
            affected.append(user)
    db.flush()
    _recompute_users(db, affected + wanted)
    return None


def _patch_members(db, tenant: Tenant, group: ScimGroup, op: str, path: str, value):
    """Add or remove members. Returns an error response, or None."""
    import re
    op = op.lower()
    match = re.fullmatch(r'members\[value eq "([^"]+)"\]', path or "", re.IGNORECASE)
    if op == "remove" and match:
        user = _member_user(db, tenant, match.group(1))
        if user is None:
            return None
        db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id,
                                         ScimGroupMember.user_id == user.id).delete()
        db.flush()
        _recompute_users(db, [user])
        return None
    if op == "remove" and (path or "").lower() in ("", "members") and not value:
        users = [db.get(User, m.user_id) for m in
                 db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).all()]
        db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).delete()
        db.flush()
        _recompute_users(db, users)
        return None
    if op == "remove":
        gone = []
        for item in _member_values(value):
            raw = item.get("value") if isinstance(item, dict) else item
            user = _member_user(db, tenant, raw)
            if user is None:
                continue
            db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id,
                                             ScimGroupMember.user_id == user.id).delete()
            gone.append(user)
        db.flush()
        _recompute_users(db, gone)
        return None
    # add or replace
    if op == "replace":
        return _set_members(db, tenant, group, value)
    for item in _member_values(value):
        raw = item.get("value") if isinstance(item, dict) else item
        user = _member_user(db, tenant, raw)
        if user is None:
            return _err(400, f"member {raw} not found", "invalidValue")
        exists = (db.query(ScimGroupMember)
                    .filter(ScimGroupMember.group_id == group.id,
                            ScimGroupMember.user_id == user.id)
                    .first())
        if exists is None:
            db.add(ScimGroupMember(tenant_id=tenant.id, group_id=group.id, user_id=user.id))
        db.flush()
        _recompute_users(db, [user])
    return None


@router.get("/Groups")
def list_groups(tenant: Tenant = Depends(scim_tenant), db: Session = Depends(get_db),
                filter: str = Query(default=""), startIndex: int = Query(default=1, ge=1),
                count: int = Query(default=100, ge=0, le=200)):
    """List/search. Okta and Entra probe with `displayName eq "Engineering"`."""
    import re
    q = db.query(ScimGroup).filter(ScimGroup.tenant_id == tenant.id)
    if filter:
        m = re.fullmatch(r'\s*displayName\s+eq\s+"([^"]+)"\s*', filter, re.IGNORECASE)
        if not m:
            return _err(501, f"unsupported filter: {filter}", "invalidFilter")
        from sqlalchemy import func
        q = q.filter(func.lower(ScimGroup.display_name) == m.group(1).lower())
    total = q.count()
    rows = q.order_by(ScimGroup.id).offset(startIndex - 1).limit(count).all()
    return JSONResponse(media_type=_SCIM_CT, content={
        "schemas": [_LIST_SCHEMA], "totalResults": total,
        "startIndex": startIndex, "itemsPerPage": len(rows),
        "Resources": [_group_resource(db, g) for g in rows],
    })


@router.post("/Groups", status_code=201)
def create_group(body: dict, tenant: Tenant = Depends(scim_tenant),
                 db: Session = Depends(get_db)):
    name = str(body.get("displayName") or "").strip()
    if not name:
        return _err(400, "displayName is required", "invalidValue")
    from sqlalchemy import func
    if (db.query(ScimGroup)
          .filter(ScimGroup.tenant_id == tenant.id,
                  func.lower(ScimGroup.display_name) == name.lower())
          .first()):
        return _err(409, f"group {name} already exists", "uniqueness")
    group = ScimGroup(tenant_id=tenant.id, display_name=name,
                      external_id=str(body.get("externalId") or "").strip())
    db.add(group)
    db.flush()
    if body.get("members"):
        blocked = _set_members(db, tenant, group, body.get("members"))
        if blocked is not None:
            return _refuse(db, blocked)
    _audit(db, tenant, "scim.group_created", name)
    _commit(db)
    db.refresh(group)
    return JSONResponse(status_code=201, media_type=_SCIM_CT, content=_group_resource(db, group))


@router.get("/Groups/{group_id}")
def get_group(group_id: str, tenant: Tenant = Depends(scim_tenant),
              db: Session = Depends(get_db)):
    try:
        return JSONResponse(media_type=_SCIM_CT,
                            content=_group_resource(db, _get_group(db, tenant, group_id)))
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)


@router.put("/Groups/{group_id}")
def replace_group(group_id: str, body: dict, tenant: Tenant = Depends(scim_tenant),
                  db: Session = Depends(get_db)):
    try:
        group = _get_group(db, tenant, group_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    name = str(body.get("displayName") or "").strip()
    if name and name != group.display_name:
        clash = (db.query(ScimGroup)
                   .filter(ScimGroup.tenant_id == tenant.id, ScimGroup.display_name == name,
                           ScimGroup.id != group.id)
                   .first())
        if clash is not None:
            return _err(409, f"group {name} already exists", "uniqueness")
        group.display_name = name
    if "externalId" in body:
        group.external_id = str(body.get("externalId") or "").strip()
    if "members" in body:
        blocked = _set_members(db, tenant, group, body.get("members"))
        if blocked is not None:
            return _refuse(db, blocked)
    else:
        # The name is part of what mappings match, so a rename reapplies everyone in it.
        members = [db.get(User, m.user_id) for m in
                   db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).all()]
        _recompute_users(db, members)
    _commit(db)
    db.refresh(group)
    return JSONResponse(media_type=_SCIM_CT, content=_group_resource(db, group))


@router.patch("/Groups/{group_id}")
def patch_group(group_id: str, body: dict, tenant: Tenant = Depends(scim_tenant),
                db: Session = Depends(get_db)):
    """The patch Okta and Entra send: add/remove `members`, replace `displayName`."""
    try:
        group = _get_group(db, tenant, group_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    renamed = False
    for op in (body.get("Operations") or []):
        name = str(op.get("op", "")).lower()
        path = str(op.get("path") or "").strip()
        value = op.get("value")
        target = path.lower()
        if not target and isinstance(value, dict):
            if "displayName" in value:
                target, value = "displayname", value.get("displayName")
            elif "members" in value:
                target, value = "members", value.get("members")
        if target == "displayname" and name in ("replace", "add") and value:
            new_name = str(value).strip()
            if new_name and new_name != group.display_name:
                group.display_name = new_name
                renamed = True
            continue
        if target == "members" or target.startswith("members["):
            blocked = _patch_members(db, tenant, group, name, path, value)
            if blocked is not None:
                return _refuse(db, blocked)
    if renamed:
        members = [db.get(User, m.user_id) for m in
                   db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).all()]
        _recompute_users(db, members)
    _commit(db)
    db.refresh(group)
    return JSONResponse(media_type=_SCIM_CT, content=_group_resource(db, group))


@router.delete("/Groups/{group_id}", status_code=204)
def delete_group(group_id: str, tenant: Tenant = Depends(scim_tenant),
                 db: Session = Depends(get_db)):
    try:
        group = _get_group(db, tenant, group_id)
    except ScimError as e:
        return _err(e.status_code, e.detail, e.scim_type)
    users = [db.get(User, m.user_id) for m in
             db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).all()]
    db.query(ScimGroupMember).filter(ScimGroupMember.group_id == group.id).delete()
    name = group.display_name
    db.delete(group)
    db.flush()
    _recompute_users(db, users)
    _audit(db, tenant, "scim.group_deleted", name)
    _commit(db)
    return Response(status_code=204)
