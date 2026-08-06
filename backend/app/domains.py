"""Domain capture: tenants claim email domains so self-serve signup can't fragment one
company into many single-user orgs.

Flow: an admin claims a domain -> we hand them a DNS TXT record (name `_palivane-verify.<domain>`,
value `palivane-domain-verify=<token>`) -> verify does a TXT lookup and flips the claim to
verified. From then on, /api/auth/signup with a matching email creates a JoinRequest for
that tenant (approved by an admin, or instantly when the domain has auto_approve) instead
of a fresh org. Free-mail providers can never be claimed.

TXT lookups go over DNS-over-HTTPS (dns.google) — no resolver library dependency, and the
target URL is fixed so there is no SSRF surface.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from . import audit_log
from .auth import require_admin
from .database import get_db
from .models import JoinRequest, TenantDomain, User

router = APIRouter(prefix="/api", tags=["domains"])

# Consumer mailbox providers: anyone can hold an address there, so a claim would let one
# customer capture every other user of that provider. Never claimable.
FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "yandex.ru", "fastmail.com", "hey.com",
    "tutanota.com", "tuta.com", "duck.com", "mail.ru", "qq.com", "163.com", "126.com",
}

_DOMAIN_RE = re.compile(r"^(?=.{4,255}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".").lstrip("@")


def txt_record_for(d: TenantDomain) -> dict:
    return {"name": f"_palivane-verify.{d.domain}", "type": "TXT",
            "value": f"palivane-domain-verify={d.token}"}


def _lookup_txt(name: str) -> list[str]:
    """TXT values for `name` via Google's DNS-over-HTTPS resolver. Fixed host, so this
    cannot be steered at internal services. Raises on transport errors (caller maps to 502)."""
    import httpx  # noqa: PLC0415

    r = httpx.get("https://dns.google/resolve", params={"name": name, "type": "TXT"},
                  timeout=10)
    r.raise_for_status()
    answers = r.json().get("Answer") or []
    # TXT data arrives quoted (possibly as multiple quoted chunks); strip the quotes.
    return [a.get("data", "").replace('"', "") for a in answers if a.get("type") == 16]


def match_verified(db: Session, email: str) -> TenantDomain | None:
    """The verified claim covering this email's domain, if any (used by signup)."""
    dom = normalize(email.rsplit("@", 1)[-1]) if "@" in email else ""
    if not dom:
        return None
    return (db.query(TenantDomain)
            .filter(TenantDomain.domain == dom, TenantDomain.verified.is_(True))
            .first())


# ---------------------------------------------------------------- domain claims (admin)

@router.get("/domains")
def list_domains(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = (db.query(TenantDomain)
            .filter(TenantDomain.tenant_id == current.tenant_id)
            .order_by(TenantDomain.id).all())
    return {"domains": [d.to_dict() | {"txt": txt_record_for(d)} for d in rows]}


@router.post("/domains")
def claim_domain(body: dict, current: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    dom = normalize(str(body.get("domain", "")))
    if not _DOMAIN_RE.match(dom):
        raise HTTPException(status_code=422, detail="not a valid domain name")
    if dom in FREE_MAIL:
        raise HTTPException(status_code=422,
                            detail="consumer mail providers cannot be claimed")
    if db.query(TenantDomain).filter(TenantDomain.domain == dom).first():
        # Deliberately identical whether it's ours or another tenant's — don't leak who.
        raise HTTPException(status_code=409, detail="that domain is already claimed")
    d = TenantDomain(tenant_id=current.tenant_id, domain=dom,
                     token=secrets.token_urlsafe(24))
    db.add(d)
    db.commit()
    db.refresh(d)
    audit_log.record(db, current.tenant_id, current.email, "domain.claim", target=dom)
    return d.to_dict() | {"txt": txt_record_for(d)}


@router.post("/domains/{domain_id}/verify")
def verify_domain(domain_id: int, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    d = db.get(TenantDomain, domain_id)
    if d is None or d.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="domain not found")
    if d.verified:
        return d.to_dict()
    expect = f"palivane-domain-verify={d.token}"
    try:
        found = _lookup_txt(f"_palivane-verify.{d.domain}")
    except Exception:
        raise HTTPException(status_code=502, detail="DNS lookup failed — try again")
    if expect not in found:
        raise HTTPException(
            status_code=409,
            detail="TXT record not found (or not propagated yet) — "
                   f"expected {expect!r} at _palivane-verify.{d.domain}")
    d.verified = True
    d.verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "domain.verify", target=d.domain)
    return d.to_dict()


@router.patch("/domains/{domain_id}")
def update_domain(domain_id: int, body: dict, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    d = db.get(TenantDomain, domain_id)
    if d is None or d.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="domain not found")
    if "auto_approve" in body:
        d.auto_approve = bool(body["auto_approve"])
        db.commit()
        audit_log.record(db, current.tenant_id, current.email, "domain.update",
                         target=d.domain, detail={"auto_approve": d.auto_approve})
    return d.to_dict()


@router.delete("/domains/{domain_id}")
def delete_domain(domain_id: int, current: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    d = db.get(TenantDomain, domain_id)
    if d is None or d.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="domain not found")
    db.delete(d)
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "domain.delete", target=d.domain)
    return {"ok": True}


# ---------------------------------------------------------------- join requests (admin)

@router.get("/join-requests")
def list_join_requests(current: User = Depends(require_admin),
                       db: Session = Depends(get_db), status: str = "pending"):
    q = db.query(JoinRequest).filter(JoinRequest.tenant_id == current.tenant_id)
    if status != "all":
        q = q.filter(JoinRequest.status == status)
    return {"requests": [r.to_dict() for r in q.order_by(JoinRequest.id.desc()).all()]}


def approve(db: Session, req: JoinRequest, decided_by: str) -> User:
    """Create the user from the parked hash and mark the request. Shared by the admin
    endpoint and the auto_approve signup path. Caller commits via this function."""
    from .metering import check_resource_quota
    check_resource_quota(db, req.tenant_id, "users",
                         db.query(User).filter(User.tenant_id == req.tenant_id).count())
    user = User(tenant_id=req.tenant_id, email=req.email,
                password_hash=req.password_hash, role="analyst")
    req.status = "approved"
    req.decided_at = datetime.now(timezone.utc).replace(tzinfo=None)
    req.decided_by = decided_by
    db.add(user)
    db.commit()
    db.refresh(user)
    audit_log.record(db, req.tenant_id, decided_by, "join.approve", target=req.email)
    return user


@router.get("/auth/join/confirm")
def confirm_join(token: str, db: Session = Depends(get_db)):
    """Landing for the emailed confirm link. Unauthenticated by design — the signed token
    is the credential. Proves mailbox ownership, then either auto-joins (when the claim
    has auto_approve) or flags the request verified and notifies the tenant's admins.
    Always redirects to the console with a status fragment (it's clicked from an inbox)."""
    from fastapi.responses import RedirectResponse  # noqa: PLC0415
    from . import email as email_mod
    from .models import Tenant
    from .security import TokenError, decode_token

    def bounce(state: str) -> RedirectResponse:
        return RedirectResponse(f"{email_mod.base_url()}/#join={state}")

    try:
        payload = decode_token(token)
    except TokenError:
        return bounce("invalid")
    if payload.get("typ") != "join":
        return bounce("invalid")
    req = db.get(JoinRequest, int(payload.get("sub", 0)))
    if req is None or req.status != "pending":
        return bounce("invalid")
    tenant = db.get(Tenant, req.tenant_id)
    if tenant is None or tenant.status == "suspended":
        return bounce("invalid")
    req.email_verified = True
    db.commit()

    claim = match_verified(db, req.email)
    if claim is not None and claim.tenant_id == req.tenant_id and claim.auto_approve:
        if db.query(User).filter(User.tenant_id == req.tenant_id,
                                 User.email == req.email).first():
            return bounce("invalid")
        approve(db, req, f"auto ({claim.domain})")
        return bounce("approved")

    admins = (db.query(User).filter(User.tenant_id == req.tenant_id, User.role == "admin",
                                    User.active.is_(True)).all())
    for a in admins:
        email_mod.send(
            a.email, f"Palivane join request: {req.email}",
            f"{req.email} verified their address and requests to join your "
            f"\"{tenant.name or tenant.slug}\" organization on Palivane.\n\n"
            f"Approve or deny it on the Team page: {email_mod.base_url()}\n\n"
            "(Their mailbox ownership is confirmed — they clicked a link sent to it.)")
    return bounce("verified")


@router.post("/join-requests/{request_id}/approve")
def approve_join(request_id: int, current: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """NOTE for admins: domain ownership was verified, but the requester's control of
    this mailbox was not — confirm out-of-band that this person made the request."""
    req = db.get(JoinRequest, request_id)
    if req is None or req.tenant_id != current.tenant_id or req.status != "pending":
        raise HTTPException(status_code=404, detail="pending request not found")
    if db.query(User).filter(User.tenant_id == req.tenant_id,
                             User.email == req.email).first():
        req.status = "denied"
        req.decided_at = datetime.now(timezone.utc).replace(tzinfo=None)
        req.decided_by = current.email
        db.commit()
        raise HTTPException(status_code=409, detail="a user with that email already exists")
    user = approve(db, req, current.email)
    # Close the loop: on the auto_approve path the requester lands in the console
    # immediately, but a manually approved requester would otherwise never hear back.
    from . import email as email_mod
    from .models import Tenant
    tenant = db.get(Tenant, req.tenant_id)
    email_mod.send(
        req.email, f"You're in — {tenant.name or tenant.slug} on Palivane",
        f"An admin approved your request to join the \"{tenant.name or tenant.slug}\" "
        f"organization on Palivane.\n\n"
        f"Sign in with the password you chose when you requested to join:\n"
        f"{email_mod.base_url()}")
    return user.to_dict()


@router.post("/join-requests/{request_id}/deny")
def deny_join(request_id: int, current: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    req = db.get(JoinRequest, request_id)
    if req is None or req.tenant_id != current.tenant_id or req.status != "pending":
        raise HTTPException(status_code=404, detail="pending request not found")
    req.status = "denied"
    req.decided_at = datetime.now(timezone.utc).replace(tzinfo=None)
    req.decided_by = current.email
    db.commit()
    audit_log.record(db, req.tenant_id, current.email, "join.deny", target=req.email)
    return req.to_dict()
