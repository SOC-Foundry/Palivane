"""Public read-only demo — "see it with sample data" before installing anything.

POST /api/auth/demo mints a short-lived session into the tenant named by
PALIVANE_DEMO_ORG (seed it with `python -m app.seed`; the `demo` slug is already
excluded from funnel analytics). The token carries a `demo` claim that
get_current_user enforces as read-only, so a shared demo org looks the same for
every visitor. Dark until PALIVANE_DEMO_ORG is set.

The session is an ADMIN one, so a visitor can open every console page (the precision readout,
the allowlist, Discovery, Fleet, Audit...) and see the sample org the way a buyer's admin would.
Nothing about that is writable: get_current_user refuses every non-GET for a demo token, and
DEMO_BLOCKED_GET below closes the few GETs that would write by another route.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .auth import _client_ip
from .config import settings
from .database import get_db
from .models import LoginAttempt, Tenant, User
from .security import create_token, hash_password

router = APIRouter(prefix="/api", tags=["demo"])

DEMO_VIEWER = "viewer@demo.local"

# GETs a demo session may not make even though it is an admin and the method is a read:
#  - /api/slack/install returns a signed "Add to Slack" URL bound to the tenant; finishing that
#    OAuth in the visitor's own workspace would write a Slack connection into the shared demo org.
#  - the bulk exports hand a visitor the whole org as files, which is not what a tour needs.
# Prefixes, matched on the request path. Anything new that mints a token or a link bound to the
# tenant belongs here (tests/test_demo.py walks every route to keep the write side honest).
# GET /api/siem/s3/role-setup also writes: it mints siem_s3_external_id on first call when
# role delivery is configured. It predates the demo session and the console does not call
# it. Until that route stops committing, it belongs in this tuple, and the route walk
# should fail when a GET commits. #291
DEMO_BLOCKED_GET = (
    "/api/slack/install",
    "/api/export/",
    "/api/audit/export",
    "/api/corpus/export",
    "/api/ml/corpus/export",
)


def blocked_for_demo(path: str) -> bool:
    return path.startswith(DEMO_BLOCKED_GET)


def enabled() -> bool:
    return bool(settings.demo_org)


@router.post("/auth/demo")
def demo_login(request: Request, db: Session = Depends(get_db)):
    """A ready-to-browse analyst session in the demo org. Same response shape as
    /auth/login so the console signs in with no special handling."""
    if not enabled():
        raise HTTPException(status_code=404, detail="no public demo on this deployment")
    tenant = db.query(Tenant).filter(Tenant.slug == settings.demo_org).first()
    if tenant is None:
        raise HTTPException(status_code=503,
                            detail="demo org is not seeded yet (run python -m app.seed)")
    # Public token mint — per-IP throttle (piggybacks the login-attempt table) so one
    # source can't spin unlimited sessions.
    ip = _client_ip(request)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.login_window)
    if ip and (db.query(LoginAttempt)
               .filter(LoginAttempt.email == "__demo__", LoginAttempt.ip == ip,
                       LoginAttempt.created_at >= cutoff).count()
               >= settings.login_ip_max_fails):
        raise HTTPException(status_code=429, detail="too many demo sessions, try again later")
    db.add(LoginAttempt(email="__demo__", ip=ip))
    db.commit()

    user = (db.query(User)
            .filter(User.tenant_id == tenant.id, User.email == DEMO_VIEWER).first())
    if user is None:
        # Unguessable password on purpose: this account is only ever entered through the demo
        # token, and that token cannot write.
        user = User(tenant_id=tenant.id, email=DEMO_VIEWER,
                    password_hash=hash_password(secrets.token_urlsafe(32)),
                    role="admin")
        db.add(user)
        db.commit()
        db.refresh(user)
    elif user.role != "admin":
        # The viewer used to be an analyst (Findings only); an existing demo org still has that row.
        user.role = "admin"
        db.commit()
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version, "demo": True},
                         ttl=3600)
    return {"access_token": token, "token_type": "bearer",
            "user": user.to_dict(), "tenant": tenant.to_dict(), "demo": True}
