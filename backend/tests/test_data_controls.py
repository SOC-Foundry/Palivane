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
    client.post("/api/apikeys", json={"label": "k", "actor": "a@acme.com"})
    client.post("/api/analyze", json={"content": "hi", "persist": True})
    client.patch("/api/tenant", json={"name": "Acme"})   # writes an audit row

    # Wrong confirmation is refused.
    assert client.request("DELETE", "/api/tenant", json={"confirm": "wrong"}).status_code == 400

    r = client.request("DELETE", "/api/tenant", json={"confirm": "acme"})
    assert r.status_code == 200 and r.json()["deleted_tenant"] == "acme"
    deleted = r.json()["deleted"]
    assert deleted["api_keys"] >= 1 and deleted["audit_log"] >= 1   # not just findings/users

    # The admin user is gone too, so the session no longer authenticates.
    assert client.get("/api/upstreams").status_code == 401
    # And ALL the tenant's data is gone — a partial delete isn't a delete.
    db = db_factory()
    from app.models import ApiKey, AuditLog
    assert db.query(Tenant).filter(Tenant.slug == "acme").first() is None
    assert db.query(Finding).count() == 0
    assert db.query(ApiKey).count() == 0
    assert db.query(AuditLog).count() == 0
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