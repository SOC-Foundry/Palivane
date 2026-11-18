"""Billing — sales-led Team, with Stripe kept only for a subscription that already exists.

Team is priced by protected users, in the bands published on /pricing
(50–100, 100–500, 500–2,000, then custom). Those are ranges, quoted after an
assessment. They are not Stripe prices. The configured price ids
(STRIPE_PRICE_TEAM_MONTHLY / ANNUAL) are the old per-user amounts. Opening
Checkout against them would bill per user again, and inventing a single dollar
amount inside each range is a pricing decision this code does not get to make.
New card checkout is therefore closed. A tenant asks in the console
(POST /api/plans/upgrade) or by email; an operator sets the plan.

What stays, for an org that already paid by card:
  the customer portal (invoices, payment method, cancel), and the webhooks that
  reconcile that subscription. `quota_users` on those events is still the Stripe
  line quantity of that old subscription, not a protected-user band.

  checkout.session.completed        -> plan=team, quantity -> quota_users (once paid;
  checkout.session.async_payment_succeeded   a delayed method upgrades on this event)
  customer.subscription.updated     -> quantity / status sync
  customer.subscription.deleted     -> plan=free (never touches enterprise)

Webhook signatures are verified manually (HMAC-SHA256 per Stripe's scheme) — stdlib only,
same policy as the other outbound integrations (alerts, Cloudflare email).
enabled() is false until STRIPE_SECRET_KEY plus at least one Team price id are set.
That flag means "portal and webhooks can run", not "checkout is for sale".
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
from fastapi.concurrency import run_in_threadpool
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


# Shown on POST /billing/checkout. Stable so the console and tests can match it.
CHECKOUT_CLOSED = (
    "Team is priced by protected users and quoted after an assessment. "
    "Card checkout is closed. Start an assessment or talk to sales from "
    "Settings, Plan and usage."
)


@router.get("/billing")
def billing_status(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """What the Settings plan card needs. `enabled` means Stripe is configured for an
    existing subscription's portal and webhooks. `checkout` is always false: a new
    Team purchase is a sales conversation, not a card form."""
    tenant = db.get(Tenant, current.tenant_id)
    return {
        "enabled": enabled(),
        "checkout": False,
        "subscribed": bool(tenant.stripe_subscription_id),
        "portal": bool(tenant.stripe_customer_id),
        # Legacy subscription quantity, if any. Not a protected-user band.
        "seats": tenant.quota_users or 0,
        "intervals": [i for i, p in (("month", settings.stripe_price_team_monthly),
                                     ("year", settings.stripe_price_team_annual)) if p],
        "publishable_key": settings.stripe_publishable_key,
    }


@router.post("/billing/checkout")
def create_checkout(current: User = Depends(require_admin)):
    """Refuse a new Checkout Session.

    The published bands are ranges, and the Stripe price ids on this deployment are
    the per-user prices. Either way, creating a session would sell the wrong thing.
    `current` is the admin gate: an anonymous caller gets 401, not this 400.
    """
    del current
    raise HTTPException(status_code=400, detail=CHECKOUT_CLOSED)


@router.post("/billing/portal")
def create_portal(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Stripe customer portal (invoices, payment method, cancel) for a subscription
    that already exists. A new purchase does not start here."""
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
    # The handler does a blocking Stripe GET and sync DB work — keep it off the event loop
    # (one uvicorn process serves every request).
    return await run_in_threadpool(_handle_event, db, event)


_LIVE = ("active", "trialing", "past_due")


def _handle_event(db: Session, event: dict) -> dict:
    """Apply one verified Stripe event. Subscription events only move plan state when they
    are about the tenant's CURRENT subscription (tenant.stripe_subscription_id): a late
    event for an old or duplicate subscription must not cancel or re-seat the live one."""
    kind = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}

    if kind in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        # A completed checkout isn't necessarily paid: a delayed payment method (bank debit)
        # completes "unpaid" and settles later as async_payment_succeeded, or fails. Only a
        # paid (or free: trial, full discount) session upgrades the org.
        status = obj.get("payment_status")
        if status is not None and status not in ("paid", "no_payment_required"):
            log.info("stripe webhook: checkout session %s is %s; waiting for the payment",
                     obj.get("id"), status)
            return {"ok": True}
        tenant = _tenant_for(db, obj)
        if tenant is None:
            log.warning("stripe webhook: no tenant for checkout session %s", obj.get("id"))
            return {"ok": True}
        new_sub = obj.get("subscription") or ""
        old_sub = tenant.stripe_subscription_id or ""
        if new_sub and old_sub and new_sub != old_sub and _sub_is_live(old_sub):
            # A second concurrent checkout produced a second live subscription. Keep the
            # existing one authoritative and flag the duplicate for ops to cancel/refund —
            # auto-cancelling a paid subscription from a webhook is not a call to make here.
            log.warning("stripe webhook: tenant %s completed checkout for subscription %s "
                        "while %s is still live; keeping the existing one",
                        tenant.id, new_sub, old_sub)
            audit_log.record(db, tenant.id, "stripe", "billing.duplicate_subscription",
                             target=new_sub, detail={"kept": old_sub})
            return {"ok": True}
        tenant.stripe_customer_id = obj.get("customer") or tenant.stripe_customer_id
        tenant.stripe_subscription_id = new_sub or old_sub
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
            current = tenant.stripe_subscription_id or ""
            if current and obj.get("id") != current:
                log.info("stripe webhook: ignoring %s for non-current subscription %s "
                         "(tenant %s)", kind, obj.get("id"), tenant.id)
            elif status in ("active", "trialing"):
                tenant.stripe_subscription_id = obj.get("id")   # adopts only when none
                if (tenant.plan or "").lower() not in ("team", "enterprise"):
                    tenant.plan = "team"
                if seats and seats != (tenant.quota_users or 0):
                    tenant.quota_users = seats
                    audit_log.record(db, tenant.id, "stripe", "billing.seats",
                                     detail={"seats": seats})
            elif status in ("canceled", "unpaid", "incomplete_expired") and current:
                _downgrade(db, tenant, status)
            db.commit()

    elif kind == "customer.subscription.deleted":
        tenant = _tenant_for(db, obj)
        if (tenant is not None and tenant.stripe_subscription_id
                and obj.get("id") == tenant.stripe_subscription_id):
            _downgrade(db, tenant, "deleted")
            db.commit()

    return {"ok": True}


def _sub_is_live(sub_id: str) -> bool:
    """Whether Stripe still considers this subscription live. A Stripe outage raises 503
    so Stripe re-delivers the event rather than us guessing which subscription wins."""
    try:
        return _stripe("GET", f"/subscriptions/{sub_id}").get("status") in _LIVE
    except HTTPException as e:
        if e.status_code == 404 or "No such subscription" in str(e.detail):
            return False
        raise HTTPException(status_code=503, detail="stripe unavailable, retry") from e


def _downgrade(db: Session, tenant: Tenant, reason: str) -> None:
    """Subscription over -> Free. Enterprise is sales-managed and never auto-downgraded;
    quota override is cleared so the Free plan defaults take back over."""
    if (tenant.plan or "").lower() == "team":
        tenant.plan = "free"
        tenant.quota_users = 0
        audit_log.record(db, tenant.id, "stripe", "billing.cancelled",
                         detail={"reason": reason})
    tenant.stripe_subscription_id = ""
