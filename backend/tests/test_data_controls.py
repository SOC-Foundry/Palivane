"""Per-tenant data controls: Claude-judge opt-out, retention purge, delete-my-org."""

from __future__ import annotations

from datetime import datetime

from app.detectors.base import AnalysisInput, Category, Signal, Surface
from app.engine import engine
from app.models import Finding, Tenant


def test_judge_opt_out_skips_the_judge(monkeypatch):
    fake = Signal(category=Category.AI_GENERATED, title="judge ran", detail="",
                  weight=0.5, confidence=0.5, detector="llm_judge")
    monkeypatch.setattr(engine.judge, "analyze", lambda item: [fake])
    item = AnalysisInput(content="hello", surface=Surface.LLM_IO)
    assert any(s.title == "judge ran" for s in engine.analyze(item, include_judge=True).signals)
    assert not any(s.title == "judge ran" for s in engine.analyze(item, include_judge=False).signals)


def test_tenant_settings_update(client):
    r = client.patch("/api/tenant", json={"judge": "off", "retention_days": 30, "name": "Acme Inc"})
    assert r.status_code == 200
    b = r.json()
    assert b["judge_enabled"] is False and b["retention_days"] == 30 and b["name"] == "Acme Inc"
    # "inherit" clears the override back to null.
    assert client.patch("/api/tenant", json={"judge": "inherit"}).json()["judge_enabled"] is None
    # negative retention rejected
    assert client.patch("/api/tenant", json={"retention_days": -1}).status_code == 400


def test_judge_off_is_honored_end_to_end(client, db_factory):
    # With the tenant opted out, a persisted analysis never carries a judge signal.
    import app.engine as engine_mod
    fake = Signal(category=Category.AI_GENERATED, title="judge ran", detail="",
                  weight=0.9, confidence=0.9, detector="llm_judge")
    # (monkeypatch on the shared engine instance used by the app)
    orig = engine_mod.engine.judge.analyze
    engine_mod.engine.judge.analyze = lambda item: [fake]
    try:
        client.patch("/api/tenant", json={"judge": "off"})
        client.post("/api/analyze", json={"content": "hi there", "persist": True})
        f = client.get("/api/findings").json()["findings"][0]
        detail = client.get(f"/api/findings/{f['id']}").json()
        assert not any(s["title"] == "judge ran" for s in detail["signals"])
    finally:
        engine_mod.engine.judge.analyze = orig


def test_managed_judge_is_plan_gated(db_factory, monkeypatch):
    # On the managed SaaS the judge is operator-funded, so WARDEN_JUDGE_PLAN_GATED makes it
    # a paid entitlement: a Free tenant runs offline-only; an Enterprise tenant gets it.
    from app import service, users as users_cli
    fake = Signal(category=Category.AI_GENERATED, title="judge ran", detail="",
                  weight=0.9, confidence=0.9, detector="llm_judge")
    monkeypatch.setattr(service.engine.judge, "analyze", lambda item: [fake])
    monkeypatch.setattr(service.engine.judge, "_backends", [("x", object(), "m")])  # judge "configured"
    monkeypatch.setattr(service.settings, "judge_plan_gated", True)

    db = db_factory()
    users_cli.create_tenant(db, "freeco", "Freeco", plan="free")
    users_cli.create_tenant(db, "entco", "Entco", plan="enterprise")
    free_id = db.query(Tenant).filter(Tenant.slug == "freeco").first().id
    ent_id = db.query(Tenant).filter(Tenant.slug == "entco").first().id
    item = AnalysisInput(content="hello", surface=Surface.LLM_IO)

    free = service.run_analysis(item, persist=False, db=db, tenant_id=free_id)
    ent = service.run_analysis(item, persist=False, db=db, tenant_id=ent_id)
    assert free["judge_used"] is False
    assert not any(s["title"] == "judge ran" for s in free["signals"])
    assert ent["judge_used"] is True
    assert any(s["title"] == "judge ran" for s in ent["signals"])

    # Self-hosted (gating off, the default) runs the operator's key for everyone, incl. Free.
    monkeypatch.setattr(service.settings, "judge_plan_gated", False)
    free2 = service.run_analysis(item, persist=False, db=db, tenant_id=free_id)
    assert free2["judge_used"] is True
    assert any(s["title"] == "judge ran" for s in free2["signals"])
    db.close()


def test_retention_purge_deletes_only_old_findings(client, db_factory):
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    db.add(Finding(tenant_id=tid, content="old", created_at=datetime(2020, 1, 1)))
    db.add(Finding(tenant_id=tid, content="new"))   # created_at defaults to now
    db.commit()
    db.close()

    # retention 0 = keep forever → nothing purged
    assert client.post("/api/findings/purge").json()["deleted"] == 0
    client.patch("/api/tenant", json={"retention_days": 30})
    out = client.post("/api/findings/purge").json()
    assert out["deleted"] == 1 and out["retention_days"] == 30   # only the 2020 row


def test_delete_my_org_requires_slug_and_cascades(client, db_factory):
    from app.models import (ApiKey, AuditLog, Agent, AgentRole, DiscoveredUsage,
                            GatewayUsage, PolicyOverride)
    client.post("/api/apikeys", json={"label": "k", "actor": "a@acme.com"})
    client.post("/api/analyze", json={"content": "hi", "persist": True})
    client.patch("/api/tenant", json={"name": "Acme"})   # writes an audit row

    # Seed every remaining tenant-scoped table so we prove a *complete* delete (and that
    # db.delete(tenant) won't hit an FK violation on a FK-enforcing engine).
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    db.add_all([
        DiscoveredUsage(tenant_id=tid, actor="a@acme.com", tool="chatgpt"),
        Agent(tenant_id=tid, name="bot", prefix="ag_x"),
        AgentRole(tenant_id=tid, name="billing"),
        PolicyOverride(tenant_id=tid, scope="user", match="a@acme.com"),
        GatewayUsage(tenant_id=tid, window_start=datetime(2026, 1, 1), kind="ingest", count=1),
    ])
    db.commit(); db.close()

    # Wrong confirmation is refused.
    assert client.request("DELETE", "/api/tenant", json={"confirm": "wrong"}).status_code == 400

    r = client.request("DELETE", "/api/tenant", json={"confirm": "acme"})
    assert r.status_code == 200 and r.json()["deleted_tenant"] == "acme"
    deleted = r.json()["deleted"]
    assert deleted["api_keys"] >= 1 and deleted["audit_log"] >= 1
    assert deleted["discovered_usage"] >= 1 and deleted["agents"] >= 1
    assert deleted["agent_roles"] >= 1 and deleted["policy_overrides"] >= 1

    # The admin user is gone too, so the session no longer authenticates.
    assert client.get("/api/upstreams").status_code == 401
    # And ALL the tenant's data is gone — a partial delete isn't a delete.
    db = db_factory()
    assert db.query(Tenant).filter(Tenant.slug == "acme").first() is None
    for model in (Finding, ApiKey, AuditLog, DiscoveredUsage, Agent, AgentRole,
                  PolicyOverride, GatewayUsage):
        assert db.query(model).count() == 0, model.__name__
    db.close()


# --- DPA acceptance record ------------------------------------------------------------

def test_dpa_accept_records_version_actor_and_audit(client):
    before = client.get("/api/tenant/dpa").json()
    assert before["accepted"] is False and before["current_version"]

    r = client.post("/api/tenant/dpa", json={})   # defaults to the current version
    assert r.status_code == 200
    st = r.json()
    assert st["accepted"] is True
    assert st["version"] == st["current_version"]
    assert st["accepted_by"] == "admin@acme.com" and st["accepted_at"]

    # GET reflects it, and an audit entry was written.
    assert client.get("/api/tenant/dpa").json()["accepted"] is True
    actions = [e["action"] for e in client.get("/api/audit").json()["entries"]]
    assert "dpa.accept" in actions


def test_dpa_stale_when_version_bumped(client, monkeypatch):
    import app.auth as auth_mod
    monkeypatch.setattr(auth_mod.settings, "dpa_version", "1.0")
    client.post("/api/tenant/dpa", json={})
    assert client.get("/api/tenant/dpa").json()["accepted"] is True
    # Bumping the canonical version makes the prior acceptance stale (re-accept required).
    monkeypatch.setattr(auth_mod.settings, "dpa_version", "2.0")
    st = client.get("/api/tenant/dpa").json()
    assert st["accepted"] is False and st["version"] == "1.0" and st["current_version"] == "2.0"


def test_dpa_requires_admin(client, db_factory):
    db = db_factory()
    from app import users as users_cli
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    tok = client.post("/api/auth/login",
                      json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    assert client.get("/api/tenant/dpa", headers={"Authorization": f"Bearer {tok}"}).status_code == 403

def test_dismiss_benign_bulk_closes_only_allow_level_open(client, db_factory):
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    db.add(Finding(tenant_id=tid, severity="benign", status="open"))
    db.add(Finding(tenant_id=tid, severity="low", status="open"))
    db.add(Finding(tenant_id=tid, severity="high", status="open"))       # stays open
    db.add(Finding(tenant_id=tid, severity="benign", status="triaged"))  # untouched
    db.commit()
    db.close()

    assert client.post("/api/findings/dismiss-benign").json()["dismissed"] == 2
    # idempotent
    assert client.post("/api/findings/dismiss-benign").json()["dismissed"] == 0

    db = db_factory()
    by = {(f.severity, f.status) for f in db.query(Finding).all()}
    db.close()
    assert ("benign", "dismissed") in by and ("low", "dismissed") in by
    assert ("high", "open") in by and ("benign", "triaged") in by


def test_dismiss_benign_requires_admin(client, db_factory, monkeypatch):
    # a non-admin analyst is refused
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "viewer@acme.com", "pw12345678", role="analyst")
    db.close()
    r = client.post("/api/auth/login", json={"email": "viewer@acme.com", "password": "pw12345678"})
    tok = r.json()["access_token"]
    r = client.post("/api/findings/dismiss-benign",
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403
