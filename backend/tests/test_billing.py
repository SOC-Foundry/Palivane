"""Self-serve billing: Stripe Checkout for Team. Dark until configured; webhook-driven
plan state; Enterprise never auto-touched."""

from __future__ import annotations

import hmac
import json
import time
from hashlib import sha256

import app.billing as billing
from app.models import Tenant


def _enable(monkeypatch, monthly="price_m1", annual="price_y1", whsec="whsec_test"):
    monkeypatch.setattr(billing.settings, "stripe_secret_key", "sk_test_x")
    monkeypatch.setattr(billing.settings, "stripe_price_team_monthly", monthly)
    monkeypatch.setattr(billing.settings, "stripe_price_team_annual", annual)
    monkeypatch.setattr(billing.settings, "stripe_webhook_secret", whsec)


def _signed(payload: dict, secret="whsec_test", t=None) -> tuple[bytes, str]:
    body = json.dumps(payload).encode()
    t = int(t or time.time())
    sig = hmac.new(secret.encode(), f"{t}.".encode() + body, sha256).hexdigest()
    return body, f"t={t},v1={sig}"


def _tenant(db_factory, plan=None):
    """acme's id; the fixture creates it as Enterprise (to test gated features), so
    billing tests that need a buyable starting point pass plan="free"."""
    db = db_factory()
    try:
        t = db.query(Tenant).filter(Tenant.slug == "acme").first()
        if plan is not None:
            t.plan = plan
            db.commit()
        return t.id
    finally:
        db.close()


def test_billing_dark_by_default(client):
    r = client.get("/api/billing")
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert client.post("/api/billing/checkout", json={}).status_code == 400
    assert client.post("/api/billing/portal").status_code == 400


def test_checkout_returns_stripe_url(client, db_factory, monkeypatch):
    _enable(monkeypatch)
    seen = {}

    def fake_stripe(method, path, params=None):
        seen.update({"method": method, "path": path, "params": params})
        return {"url": "https://checkout.stripe.com/c/session123"}

    monkeypatch.setattr(billing, "_stripe", fake_stripe)
    _tenant(db_factory, plan="free")
    r = client.post("/api/billing/checkout", json={"interval": "year", "seats": 25})
    assert r.status_code == 200 and r.json()["url"].startswith("https://checkout.stripe.com/")
    assert seen["path"] == "/checkout/sessions"
    assert seen["params"]["line_items[0][price]"] == "price_y1"
    assert seen["params"]["line_items[0][quantity]"] == 25
    assert seen["params"]["mode"] == "subscription"


def test_checkout_seats_floor_is_member_count(client, db_factory, monkeypatch):
    _enable(monkeypatch)
    captured = {}
    monkeypatch.setattr(billing, "_stripe",
                        lambda m, p, params=None: captured.update(params) or {"url": "https://x"})
    _tenant(db_factory, plan="free")
    # acme has 1 user; asking for 0 seats floors to max(1, members)=1
    r = client.post("/api/billing/checkout", json={"seats": 0})
    assert r.status_code == 200 and captured["line_items[0][quantity]"] == 1


def test_webhook_rejects_bad_and_stale_signatures(raw_client, monkeypatch):
    _enable(monkeypatch)
    body, sig = _signed({"type": "noop", "data": {"object": {}}})
    ok = raw_client.post("/api/billing/webhook", content=body,
                         headers={"Stripe-Signature": sig})
    assert ok.status_code == 200
    bad = raw_client.post("/api/billing/webhook", content=body,
                          headers={"Stripe-Signature": "t=1,v1=deadbeef"})
    assert bad.status_code == 400
    stale_body, stale_sig = _signed({"type": "noop"}, t=int(time.time()) - 4000)
    stale = raw_client.post("/api/billing/webhook", content=stale_body,
                            headers={"Stripe-Signature": stale_sig})
    assert stale.status_code == 400
    none = raw_client.post("/api/billing/webhook", content=body)
    assert none.status_code == 400


def test_checkout_completed_flips_plan_and_seats(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    tid = _tenant(db_factory, plan="trial")
    monkeypatch.setattr(billing, "_stripe", lambda m, p, params=None: {
        "items": {"data": [{"quantity": 12}]}})   # the GET /subscriptions/... seat lookup
    body, sig = _signed({"type": "checkout.session.completed", "data": {"object": {
        "id": "cs_1", "object": "checkout.session", "customer": "cus_1",
        "subscription": "sub_1", "metadata": {"tenant_id": str(tid)}}}})
    r = raw_client.post("/api/billing/webhook", content=body,
                        headers={"Stripe-Signature": sig})
    assert r.status_code == 200
    db = db_factory()
    t = db.get(Tenant, tid)
    assert t.plan == "team" and t.quota_users == 12
    assert t.stripe_customer_id == "cus_1" and t.stripe_subscription_id == "sub_1"
    db.close()
    # the console now reports it
    status = client.get("/api/billing").json()
    assert status["subscribed"] is True and status["portal"] is True


def test_subscription_updated_syncs_seats(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    tid = _tenant(db_factory)
    db = db_factory()
    t = db.get(Tenant, tid)
    t.plan, t.stripe_subscription_id, t.quota_users = "team", "sub_1", 12
    db.commit(); db.close()
    body, sig = _signed({"type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "object": "subscription", "status": "active",
        "metadata": {"tenant_id": str(tid)},
        "items": {"data": [{"quantity": 30}]}}}})
    assert raw_client.post("/api/billing/webhook", content=body,
                           headers={"Stripe-Signature": sig}).status_code == 200
    db = db_factory()
    assert db.get(Tenant, tid).quota_users == 30
    db.close()


def test_subscription_deleted_downgrades_team_not_enterprise(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    tid = _tenant(db_factory)
    for start_plan, want_plan in (("team", "free"), ("enterprise", "enterprise")):
        db = db_factory()
        t = db.get(Tenant, tid)
        t.plan, t.stripe_subscription_id, t.quota_users = start_plan, "sub_9", 50
        db.commit(); db.close()
        body, sig = _signed({"type": "customer.subscription.deleted", "data": {"object": {
            "id": "sub_9", "object": "subscription", "status": "canceled",
            "metadata": {"tenant_id": str(tid)}}}})
        assert raw_client.post("/api/billing/webhook", content=body,
                               headers={"Stripe-Signature": sig}).status_code == 200
        db = db_factory()
        t = db.get(Tenant, tid)
        assert t.plan == want_plan and t.stripe_subscription_id == ""
        db.close()


def test_checkout_blocked_for_enterprise_and_double_subscribe(client, db_factory, monkeypatch):
    _enable(monkeypatch)
    tid = _tenant(db_factory)
    db = db_factory()
    db.get(Tenant, tid).plan = "enterprise"
    db.commit(); db.close()
    assert client.post("/api/billing/checkout", json={}).status_code == 400
    db = db_factory()
    t = db.get(Tenant, tid)
    t.plan, t.stripe_subscription_id = "team", "sub_live"
    db.commit(); db.close()
    assert client.post("/api/billing/checkout", json={}).status_code == 409
