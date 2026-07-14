"""Tenant lifecycle: suspension blocks sessions/logins/ingest without data loss; the
purge cascade covers domain-capture tables; purge-empty selects only abandoned signups."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import ApiKey, Finding, JoinRequest, Tenant, TenantDomain, User


def _suspend(db_factory, tenant_id=1, status="suspended"):
    db = db_factory()
    db.query(Tenant).filter(Tenant.id == tenant_id).update({"status": status})
    db.commit()
    db.close()


def test_suspension_blocks_session_login_and_ingest(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    _suspend(db_factory)
    # existing session -> 403
    assert client.get("/api/auth/me").status_code == 403
    # fresh password login -> 403 (not 401: credentials are fine, the org is off)
    r = raw_client.post("/api/auth/login",
                        json={"email": "admin@acme.com", "password": "password123"})
    assert r.status_code == 403 and "suspended" in r.json()["detail"]
    # capture ingest -> 403
    ing = raw_client.post("/api/ingest/ai-usage",
                          json={"content": "hi", "destination": "https://chatgpt.com/"},
                          headers={"X-Warden-Token": key})
    assert ing.status_code == 403

    # resume restores everything, nothing was deleted
    _suspend(db_factory, status="active")
    assert raw_client.post("/api/auth/login",
                           json={"email": "admin@acme.com",
                                 "password": "password123"}).status_code == 200


def test_delete_org_cascade_frees_claimed_domain(client, db_factory):
    client.post("/api/domains", json={"domain": "acme.com"})
    r = client.request("DELETE", "/api/tenant", json={"confirm": "acme"})
    assert r.status_code == 200
    deleted = r.json()["deleted"]
    assert deleted["domains"] == 1          # claim freed — domain can be re-claimed later
    db = db_factory()
    assert db.query(TenantDomain).count() == 0
    assert db.query(JoinRequest).count() == 0
    db.close()


def test_purge_empty_selects_only_abandoned(client, db_factory):
    from app.lifecycle import purgeable_empty_tenants, purge_tenant
    db = db_factory()
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=60)
    # abandoned: 1 user, no findings/keys, old
    t_dead = Tenant(slug="dead", name="Dead", created_at=old)
    # active-looking: has an API key
    t_live = Tenant(slug="live", name="Live", created_at=old)
    # too fresh to purge
    t_new = Tenant(slug="fresh", name="Fresh")
    db.add_all([t_dead, t_live, t_new])
    db.commit()
    db.add(User(tenant_id=t_dead.id, email="a@dead.com", password_hash="x"))
    db.add(ApiKey(tenant_id=t_live.id, prefix="ak_xxxxxxxx", token_hash="h"))
    db.commit()

    victims = purgeable_empty_tenants(db, older_than_days=30)
    assert [t.slug for t in victims] == ["dead"]
    purge_tenant(db, victims[0])
    assert db.query(Tenant).filter(Tenant.slug == "dead").count() == 0
    assert db.query(Tenant).filter(Tenant.slug.in_(["live", "fresh", "acme"])).count() == 3
    db.close()
