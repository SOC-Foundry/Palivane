"""Cross-tenant isolation (IDOR): tenant A's session must never read or mutate tenant B's
data — findings, users, API keys, domains, join requests — by guessing IDs, and list
endpoints must never leak across tenants. The cardinal multi-tenant risk; assert it hard."""

from __future__ import annotations

from app import users as users_cli
from app.models import ApiKey, Finding, JoinRequest, TenantDomain, User
from app.security import generate_api_key, hash_password


def _seed_beta(db_factory):
    """A second tenant with one of everything, returning the IDs tenant A will try to touch."""
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta Corp")
    from app.models import Tenant
    beta = db.query(Tenant).filter(Tenant.slug == "beta").first()
    u = User(tenant_id=beta.id, email="user@beta.com", password_hash=hash_password("password123"),
             role="analyst")
    f = Finding(tenant_id=beta.id, channel="llm", surface="ai_usage", sender="user@beta.com",
                subject="beta secret", content="beta confidential", risk_score=90,
                severity="critical", recommended_action="block", signals=[])
    _, prefix, th = generate_api_key()
    k = ApiKey(tenant_id=beta.id, label="beta-key", prefix=prefix, token_hash=th)
    d = TenantDomain(tenant_id=beta.id, domain="beta.com", token="tok", verified=True)
    j = JoinRequest(tenant_id=beta.id, email="new@beta.com", password_hash=hash_password("x"*12))
    db.add_all([u, f, k, d, j]); db.commit()
    ids = {"tenant": beta.id, "user": u.id, "finding": f.id, "key": k.id,
           "domain": d.id, "join": j.id}
    db.close()
    return ids


def test_cannot_read_or_mutate_other_tenants_records(client, db_factory):
    b = _seed_beta(db_factory)   # client fixture is tenant 'acme'

    # findings — read + mutate by id
    assert client.get(f"/api/findings/{b['finding']}").status_code == 404
    assert client.patch(f"/api/findings/{b['finding']}", json={"status": "dismissed"}).status_code == 404
    # users — mutate by id
    assert client.patch(f"/api/users/{b['user']}", json={"role": "admin"}).status_code == 404
    # api keys — revoke by id
    assert client.delete(f"/api/apikeys/{b['key']}").status_code == 404
    # domains — verify/patch/delete by id
    assert client.post(f"/api/domains/{b['domain']}/verify").status_code == 404
    assert client.patch(f"/api/domains/{b['domain']}", json={"auto_approve": True}).status_code == 404
    assert client.delete(f"/api/domains/{b['domain']}").status_code == 404
    # join requests — approve/deny by id
    assert client.post(f"/api/join-requests/{b['join']}/approve").status_code == 404
    assert client.post(f"/api/join-requests/{b['join']}/deny").status_code == 404


def test_list_endpoints_never_leak_across_tenants(client, db_factory):
    b = _seed_beta(db_factory)

    fids = [f["id"] for f in client.get("/api/findings").json()["findings"]]
    assert b["finding"] not in fids
    emails = [u["email"] for u in client.get("/api/users").json()["users"]]
    assert "user@beta.com" not in emails
    kids = [k["id"] for k in client.get("/api/apikeys").json()["api_keys"]]
    assert b["key"] not in kids
    doms = [d["domain"] for d in client.get("/api/domains").json()["domains"]]
    assert "beta.com" not in doms
    jids = [j["id"] for j in client.get("/api/join-requests").json()["requests"]]
    assert b["join"] not in jids


def test_stats_and_usage_are_own_tenant_only(client, db_factory):
    _seed_beta(db_factory)
    # acme has no findings; beta's critical finding must not show in acme's stats
    s = client.get("/api/stats").json()
    assert s["total"] == 0 and s["high_risk"] == 0


# ---------------------------------------------------------------------------------------
# Two live tenants seeded through the REAL API/ingest path (not raw DB inserts), proving
# A's token can read ONLY A's rows on findings / apikeys / audit / discovery-inventory,
# and cannot fetch B's finding or revoke B's key by id. Complements the raw-insert IDOR
# tests above by exercising the ingest + auth stack end to end.
# ---------------------------------------------------------------------------------------

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def _make_tenant(db_factory, slug: str):
    """Create <slug> with an admin, return an authenticated admin TestClient."""
    db = db_factory()
    users_cli.create_tenant(db, slug, slug.title(), plan="enterprise")
    users_cli.create_user(db, slug, f"admin@{slug}.com", "password123", "admin")
    db.close()
    c = TestClient(app)
    tok = c.post("/api/auth/login",
                 json={"email": f"admin@{slug}.com", "password": "password123"}).json()
    c.headers.update({"Authorization": f"Bearer {tok['access_token']}"})
    return c


def _seed_via_api(c: TestClient, prompt: str):
    """Mint an API key and drive a finding through the real ingest path. Returns
    (api_key_id, finding_id)."""
    k = c.post("/api/apikeys", json={"label": f"key", "actor": "svc@x"}).json()
    key_id, token = k["id"], k["token"]
    body = c.post("/api/ingest/ai-usage",
                  json={"content": prompt, "tool": "chatgpt", "destination": "chatgpt"},
                  headers={"X-Palivane-Token": token}).json()
    fid = body.get("finding_id")
    assert fid is not None, f"ingest did not persist a finding: {body}"
    return key_id, fid


def _two_live_tenants(db_factory):
    a = _make_tenant(db_factory, "alpha")
    b = _make_tenant(db_factory, "bravo")
    # Each tenant gets a distinct, risky finding (a secret leak -> persisted).
    a_key, a_find = _seed_via_api(a, "here is our key AKIAIOSFODNN7EXAMPLE for alpha")
    b_key, b_find = _seed_via_api(b, "bravo secret AKIA1234567890ABCDEF ssn 123-45-6789")
    return a, b, {"a_key": a_key, "a_find": a_find, "b_key": b_key, "b_find": b_find}


def test_findings_list_is_tenant_scoped(db_factory):
    a, b, ids = _two_live_tenants(db_factory)
    a_ids = [f["id"] for f in a.get("/api/findings").json()["findings"]]
    b_ids = [f["id"] for f in b.get("/api/findings").json()["findings"]]
    assert ids["a_find"] in a_ids and ids["b_find"] not in a_ids, "A saw B's finding!"
    assert ids["b_find"] in b_ids and ids["a_find"] not in b_ids, "B saw A's finding!"


def test_finding_by_id_cross_tenant_is_404(db_factory):
    a, b, ids = _two_live_tenants(db_factory)
    # A fetching B's finding by id -> 404 (not 200 with B's content).
    assert a.get(f"/api/findings/{ids['b_find']}").status_code == 404
    assert b.get(f"/api/findings/{ids['a_find']}").status_code == 404
    # And A can read its own.
    assert a.get(f"/api/findings/{ids['a_find']}").status_code == 200


def test_apikeys_list_is_tenant_scoped(db_factory):
    a, b, ids = _two_live_tenants(db_factory)
    a_keys = [k["id"] for k in a.get("/api/apikeys").json()["api_keys"]]
    b_keys = [k["id"] for k in b.get("/api/apikeys").json()["api_keys"]]
    assert ids["a_key"] in a_keys and ids["b_key"] not in a_keys, "A saw B's api key!"
    assert ids["b_key"] in b_keys and ids["a_key"] not in b_keys


def test_apikey_revoke_cross_tenant_denied(db_factory):
    a, b, ids = _two_live_tenants(db_factory)
    # A trying to revoke B's key -> 404, and B's key stays active.
    assert a.delete(f"/api/apikeys/{ids['b_key']}").status_code == 404
    still = [k for k in b.get("/api/apikeys").json()["api_keys"] if k["id"] == ids["b_key"]]
    assert still and still[0].get("active", True) is True, "cross-tenant revoke took effect!"
    # A can revoke its own.
    assert a.delete(f"/api/apikeys/{ids['a_key']}").status_code == 200


def test_audit_is_tenant_scoped_live(db_factory):
    a, b, ids = _two_live_tenants(db_factory)
    a_targets = [e.get("target") for e in a.get("/api/audit").json()["entries"]]
    b_targets = [e.get("target") for e in b.get("/api/audit").json()["entries"]]
    # apikey.create was audited under each tenant; neither log leaks the other's actor.
    assert "svc@x" in a_targets or any("key" in str(t) for t in a_targets)
    a_actors = {e.get("actor") for e in a.get("/api/audit").json()["entries"]}
    assert "admin@bravo.com" not in a_actors, "A's audit log leaked B's admin!"
    b_actors = {e.get("actor") for e in b.get("/api/audit").json()["entries"]}
    assert "admin@alpha.com" not in b_actors


def test_discovery_inventory_is_tenant_scoped(db_factory):
    a, b, ids = _two_live_tenants(db_factory)
    a_inv = a.get("/api/discovery/inventory")
    b_inv = b.get("/api/discovery/inventory")
    assert a_inv.status_code == 200 and b_inv.status_code == 200
    # The inventory is derived from findings; A's must reflect A's activity only. Assert
    # no bravo-specific actor/tool leaks into alpha's inventory blob and vice versa.
    assert "bravo" not in a_inv.text.lower(), "discovery inventory leaked bravo into alpha!"
    assert "alpha" not in b_inv.text.lower(), "discovery inventory leaked alpha into bravo!"
