"""Self-serve billing — Stripe Checkout for the Team plan.

The sales-led path (app/main.py /api/plans/upgrade, the operator CLI set-plan) stays for
Enterprise; this is the card-swipe path for Team: a per-seat Stripe subscription bought
through Checkout, managed through the Stripe customer portal. Dark by default — enabled()
is false until STRIPE_SECRET_KEY plus at least one Team price id are set, and the console
falls back to the sales-led upgrade request, so nothing changes for deployments without a
Stripe account.

Plan state stays authoritative in the tenants row; Stripe webhooks move it:
  checkout.session.completed        -> plan=team, seats -> quota_users
  customer.subscription.updated     -> seat / status sync
  customer.subscription.deleted     -> plan=free (never touches enterprise)
Webhook signatures are verified manually (HMAC-SHA256 per Stripe's scheme) — stdlib only,
same policy as the other outbound integrations (alerts, Cloudflare email).
"""

from __future__ import annotations

import hmac
import json
import logging
import time
import urllib.parse
import urllib.request
from hashlib import sha256

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import audit_log
from .auth import require_admin
from .config import settings
from .database import get_db
from .models import Tenant, User

log = logging.getLogger("uvicorn.error")
router = APIRouter(prefix="/api", tags=["billing"])

_API = "https://api.stripe.com/v1"


def enabled() -> bool:
    return bool(settings.stripe_secret_key and
                (settings.stripe_price_team_monthly or settings.stripe_price_team_annual))


def _stripe(method: str, path: str, params: dict | None = None) -> dict:
    """One Stripe REST call (form-encoded, like their SDKs). Raises HTTPException on
    Stripe-side errors so callers surface a clean message instead of a stack trace."""
    data = urllib.parse.urlencode(params or {}).encode() if params else None
    req = urllib.request.Request(
        f"{_API}{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {settings.stripe_secret_key}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = "billing provider error"
        try:
            detail = json.loads(e.read()).get("error", {}).get("message", detail)
        except Exception:
            pass
        log.warning("stripe %s %s failed: %s", method, path, detail[:200])
        # NOT 502: Cloudflare replaces origin 502/504 bodies with its own error page,
        # which hides the actual Stripe message from the console (and from curl).
        raise HTTPException(status_code=400, detail=f"Stripe: {detail[:300]}")
    except HTTPException:
        raise
    except Exception as e:
        log.warning("stripe %s %s failed: %s", method, path, str(e)[:200])
        raise HTTPException(status_code=503, detail="billing provider unreachable")


def _base_url() -> str:
    return settings.public_base_url or "http://localhost:5173"


def _price_for(interval: str) -> str:
    price = {"month": settings.stripe_price_team_monthly,
             "year": settings.stripe_price_team_annual}.get(interval, "")
    if not price:
        raise HTTPException(status_code=400,
                            detail=f"{interval}ly billing is not available here")
    return price


@router.get("/billing")
def billing_status(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """What the Settings plan card needs: is self-serve on, and where does this org stand."""
    tenant = db.get(Tenant, current.tenant_id)
    return {
        "enabled": enabled(),
        "subscribed": bool(tenant.stripe_subscription_id),
        "portal": bool(tenant.stripe_customer_id),
        "seats": tenant.quota_users or 0,
        "intervals": [i for i, p in (("month", settings.stripe_price_team_monthly),
                                     ("year", settings.stripe_price_team_annual)) if p],
        # Publishable key (pk_…) — not a secret; the frontend needs it to mount the
        # embedded Checkout via Stripe.js.
        "publishable_key": settings.stripe_publishable_key,
    }


class CheckoutRequest(BaseModel):
    interval: str = "month"      # month | year
    seats: int = 5


@router.post("/billing/checkout")
def create_checkout(body: CheckoutRequest, current: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """Start a per-seat Team subscription as an EMBEDDED Checkout Session — mounted on our
    own page (ui_mode=embedded), so the buyer never leaves the console. Returns the
    session's client_secret for Stripe.js to render. The plan flips only when the
    checkout.session.completed webhook lands — never here."""
    if not enabled():
        raise HTTPException(status_code=400, detail="self-serve billing is not configured")
    tenant = db.get(Tenant, current.tenant_id)
    if (tenant.plan or "").lower() == "enterprise":
        raise HTTPException(status_code=400,
                            detail="Enterprise plans are managed with sales, not by card")
    if tenant.stripe_subscription_id:
        raise HTTPException(status_code=409,
                            detail="already subscribed — use 'Manage billing' to change seats")
    seats = max(1, min(int(body.seats or 1), 1000))
    users = db.query(User).filter(User.tenant_id == tenant.id).count()
    seats = max(seats, users)   # can't buy fewer seats than existing members
    params = {
        "mode": "subscription",
        # Stripe renamed the embedded value: current API rejects "embedded" and wants
        # "embedded_page" (the full prebuilt checkout mounted in-page via client_secret).
        "ui_mode": "embedded_page",
        "line_items[0][price]": _price_for(body.interval),
        "line_items[0][quantity]": seats,
        "line_items[0][adjustable_quantity][enabled]": "true",
        "line_items[0][adjustable_quantity][minimum]": max(1, users),
        "line_items[0][adjustable_quantity][maximum]": 1000,
        "client_reference_id": tenant.id,
        "subscription_data[metadata][tenant_id]": tenant.id,
        "metadata[tenant_id]": tenant.id,
        "allow_promotion_codes": "true",
        # On completion Stripe redirects the embedded flow back to our own page — still on
        # our domain start to finish. The webhook (not this URL) is what flips the plan.
        "return_url": f"{_base_url()}/#billing=success",
    }
    # Reuse the Stripe customer across attempts so retries and re-subscribes don't
    # spawn duplicate customer records.
    if tenant.stripe_customer_id:
        params["customer"] = tenant.stripe_customer_id
    else:
        params["customer_email"] = current.email
    session = _stripe("POST", "/checkout/sessions", params)
    audit_log.record(db, tenant.id, current.email, "billing.checkout",
                     target="team", detail={"seats": seats, "interval": body.interval})
    return {"client_secret": session["client_secret"]}


@router.post("/billing/portal")
def create_portal(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Stripe customer portal (invoices, payment method, seat changes, cancel)."""
    tenant = db.get(Tenant, current.tenant_id)
    if not (enabled() and tenant.stripe_customer_id):
        raise HTTPException(status_code=400, detail="no billing account for this org yet")
    session = _stripe("POST", "/billing_portal/sessions",
                      {"customer": tenant.stripe_customer_id,
                       "return_url": f"{_base_url()}/#billing"})
    return {"url": session["url"]}


def _verify_signature(payload: bytes, header: str, tolerance: int = 300) -> bool:
    """Stripe-Signature: t=<unix>,v1=<hmac>[,v1=...]. HMAC-SHA256 of "{t}.{payload}"
    with the webhook signing secret; constant-time compare; reject stale timestamps
    (replay window)."""
    t, candidates = "", []
    for part in header.split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            t = v
        elif k == "v1":
            candidates.append(v)
    if not t or not candidates:
        return False
    try:
        ts = int(t)
    except ValueError:
        return False   # malformed timestamp in the header -> reject cleanly (400), never 500
    if abs(time.time() - ts) > tolerance:
        return False
    expected = hmac.new(settings.stripe_webhook_secret.encode(),
                        f"{t}.".encode() + payload, sha256).hexdigest()
    return any(hmac.compare_digest(expected, c) for c in candidates)


def _tenant_for(db: Session, obj: dict) -> Tenant | None:
    """Resolve the tenant a Stripe object belongs to: our metadata first (we stamp
    tenant_id on the session AND the subscription), subscription id as the fallback."""
    tid = (obj.get("metadata") or {}).get("tenant_id") or obj.get("client_reference_id")
    if tid and str(tid).isdigit():
        return db.get(Tenant, int(tid))
    sub = obj.get("id") if str(obj.get("object")) == "subscription" else obj.get("subscription")
    if sub:
        return db.query(Tenant).filter(Tenant.stripe_subscription_id == sub).first()
    return None


def _sub_quantity(sub: dict) -> int:
    items = ((sub.get("items") or {}).get("data") or [{}])
    return int(items[0].get("quantity") or 0)


@router.post("/billing/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Stripe -> plan state. Public endpoint; trust comes from the signature, and every
    outcome is idempotent (re-delivered events settle on the same row state)."""
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=400, detail="webhooks not configured")
    payload = await request.body()
    if not _verify_signature(payload, request.headers.get("Stripe-Signature", "")):
        raise HTTPException(status_code=400, detail="bad signature")
    event = json.loads(payload)
    kind = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}

    if kind == "checkout.session.completed":
        tenant = _tenant_for(db, obj)
        if tenant is None:
            log.warning("stripe webhook: no tenant for checkout session %s", obj.get("id"))
            return {"ok": True}
        tenant.stripe_customer_id = obj.get("customer") or tenant.stripe_customer_id
        tenant.stripe_subscription_id = obj.get("subscription") or tenant.stripe_subscription_id
        seats = 0
        if tenant.stripe_subscription_id:
            try:
                seats = _sub_quantity(_stripe("GET",
                                              f"/subscriptions/{tenant.stripe_subscription_id}"))
            except HTTPException:
                pass   # seat sync arrives with the subscription.updated event anyway
        if (tenant.plan or "").lower() != "enterprise":
            tenant.plan = "team"
        if seats:
            tenant.quota_users = seats
        db.commit()
        audit_log.record(db, tenant.id, "stripe", "billing.subscribed",
                         target="team", detail={"seats": seats})

    elif kind == "customer.subscription.updated":
        tenant = _tenant_for(db, obj)
        if tenant is not None:
            status = obj.get("status", "")
            seats = _sub_quantity(obj)
            if status in ("active", "trialing"):
                tenant.stripe_subscription_id = obj.get("id")
                if (tenant.plan or "").lower() not in ("team", "enterprise"):
                    tenant.plan = "team"
                if seats and seats != (tenant.quota_users or 0):
                    tenant.quota_users = seats
                    audit_log.record(db, tenant.id, "stripe", "billing.seats",
                                     detail={"seats": seats})
            elif status in ("canceled", "unpaid", "incomplete_expired"):
                _downgrade(db, tenant, status)
            db.commit()

    elif kind == "customer.subscription.deleted":
        tenant = _tenant_for(db, obj)
        if tenant is not None:
            _downgrade(db, tenant, "deleted")
            db.commit()

    return {"ok": True}


def _downgrade(db: Session, tenant: Tenant, reason: str) -> None:
    """Subscription over -> Free. Enterprise is sales-managed and never auto-downgraded;
    quota override is cleared so the Free plan defaults take back over."""
    if (tenant.plan or "").lower() == "team":
        tenant.plan = "free"
        tenant.quota_users = 0
        audit_log.record(db, tenant.id, "stripe", "billing.cancelled",
                         detail={"reason": reason})
    tenant.stripe_subscription_id = ""
