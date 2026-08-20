"""Signup→activation funnel aggregation + operator-token-gated endpoint."""

from __future__ import annotations

import hmac

from app import funnel, users as users_cli
from app.models import ApiKey, Finding, Tenant, User


def _seed_tenant(db, slug, *, verified, key, finding):
    users_cli.create_tenant(db, slug, slug)
    t = db.query(Tenant).filter(Tenant.slug == slug).first()
    u = User(tenant_id=t.id, email=f"a@{slug}.com", password_hash="x",
             role="admin", email_verified=verified)
    db.add(u)
    if key:
        db.add(ApiKey(tenant_id=t.id, label="k", actor="a", prefix="ak_x", token_hash="h"))
    if finding:
        db.add(Finding(tenant_id=t.id, surface="ai_usage", risk_score=10, severity="low"))
    db.commit()
    return t


def test_funnel_stages_are_monotonic_subsets(db_factory):
    db = db_factory()
    _seed_tenant(db, "signedonly", verified=False, key=False, finding=False)
    _seed_tenant(db, "verifiedonly", verified=True, key=False, finding=False)
    _seed_tenant(db, "connected", verified=True, key=True, finding=False)
    _seed_tenant(db, "activated", verified=True, key=True, finding=True)
    f = funnel.compute(db)
    s = f["stages"]
    assert s["signed_up"] == 4
    assert s["verified"] == 3
    assert s["connected"] == 2
    assert s["activated"] == 1
    # end-to-end conversion is activated/signed_up
    assert f["conversion"]["activated_of_signed_up"] == 25.0
    db.close()


def test_funnel_excludes_internal_by_default(db_factory):
    db = db_factory()
    _seed_tenant(db, "palivane", verified=True, key=True, finding=True)
    _seed_tenant(db, "demo", verified=True, key=True, finding=True)
    _seed_tenant(db, "realco", verified=True, key=True, finding=True)
    assert funnel.compute(db)["stages"]["signed_up"] == 1            # only realco
    assert funnel.compute(db, include_internal=True)["stages"]["signed_up"] == 3
    db.close()


def test_funnel_stuck_list_is_verified_never_activated(db_factory):
    db = db_factory()
    _seed_tenant(db, "stuck1", verified=True, key=True, finding=False)
    _seed_tenant(db, "stuck2", verified=True, key=False, finding=False)
    _seed_tenant(db, "done", verified=True, key=True, finding=True)
    _seed_tenant(db, "unverified", verified=False, key=False, finding=False)  # not "stuck"
    stuck = {o["slug"] for o in funnel.compute(db)["stuck_orgs"]}
    assert stuck == {"stuck1", "stuck2"}
    db.close()


def test_funnel_endpoint_requires_metrics_token(client, raw_client, monkeypatch):
    from app import main
    # No token configured -> 404 (can't be left open by accident).
    monkeypatch.setattr(main.settings, "metrics_token", "")
    assert raw_client.get("/api/admin/funnel").status_code == 404
    # Token configured -> 401 without it, 200 with it. A tenant session must NOT grant access.
    monkeypatch.setattr(main.settings, "metrics_token", "s3cret-metrics")
    assert raw_client.get("/api/admin/funnel").status_code == 401
    assert client.get("/api/admin/funnel").status_code == 401   # tenant JWT is not enough
    ok = raw_client.get("/api/admin/funnel", headers={"Authorization": "Bearer s3cret-metrics"})
    assert ok.status_code == 200 and "stages" in ok.json()
