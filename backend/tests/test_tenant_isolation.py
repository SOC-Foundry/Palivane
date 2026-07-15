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
