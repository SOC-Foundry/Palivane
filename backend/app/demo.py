"""Public read-only demo — "see it with sample data" before installing anything.

POST /api/auth/demo mints a short-lived session into the tenant named by
PALIVANE_DEMO_ORG (seed it with `python -m app.seed`; the `demo` slug is already
excluded from funnel analytics). The token carries a `demo` claim that
get_current_user enforces as read-only, so a shared demo org looks the same for
every visitor. Dark until PALIVANE_DEMO_ORG is set.
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
        # Unguessable password on purpose: this account is only ever entered through
        # the demo token; the analyst role keeps admin tabs out of the tour.
        user = User(tenant_id=tenant.id, email=DEMO_VIEWER,
                    password_hash=hash_password(secrets.token_urlsafe(32)),
                    role="analyst")
        db.add(user)
        db.commit()
        db.refresh(user)
    token = create_token({"sub": str(user.id), "tenant_id": user.tenant_id,
                          "role": user.role, "tv": user.token_version, "demo": True},
                         ttl=3600)
    return {"access_token": token, "token_type": "bearer",
            "user": user.to_dict(), "tenant": tenant.to_dict(), "demo": True}
