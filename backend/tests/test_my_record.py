"""Your record (app/my_record.py): what Palivane holds about one person, told to that person,
and its export."""
from __future__ import annotations

import json

from app import users as users_cli
from app.config import settings
from app.detectors.base import AnalysisInput, Surface
from app.models import AuditLog, SensorHeartbeat, Tenant
from app.service import run_analysis

AWS = "AKIA" + "IOSFODNN7" + "QXAMPLE"
SSN = "Patient Jane Doe, DOB 1980-04-02, SSN 123-45-6789, diagnosed with type 2 diabetes"


def _tenant(db) -> Tenant:
    return db.query(Tenant).order_by(Tenant.id).first()


def _member(raw_client, db, email="sam@acme.com"):
    users_cli.create_user(db, _tenant(db).slug, email, "password123", "member")
    tok = raw_client.post("/api/auth/login", json={"email": email, "password": "password123"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def _event(db, tid, text, actor, channel="chatgpt", surface=Surface.AI_USAGE):
    return run_analysis(AnalysisInput(content=text, sender=actor, channel=channel, surface=surface, subject="prompt"),
                        persist=True, db=db, tenant_id=tid)


def test_empty_record_for_a_new_person(client, raw_client, db_factory):
    db = db_factory()
    h = _member(raw_client, db)
    r = raw_client.get("/api/my/record", headers=h)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["email"] == "sam@acme.com" and d["captured"]["findings"] == 0
    assert d["sensors"] == [] and d["contained"] is None and d["left_the_org"]["total"] == 0
    assert "retention" in d["stored"]["how_long"].lower() or "kept" in d["stored"]["how_long"].lower()
    assert d["rights"]["export"] == "/api/my/record/export"


def test_record_counts_only_my_findings_and_says_what_is_stored(client, raw_client, db_factory, monkeypatch):
    monkeypatch.setattr(settings, "gateway_enforce_secrets", False)
    db = db_factory()
    tid = _tenant(db).id
    h = _member(raw_client, db)
    _event(db, tid, f"deploy with {AWS}", "sam@acme.com", channel="claude-code")
    _event(db, tid, SSN, "sam@acme.com")
    _event(db, tid, f"why does {AWS} fail", "other@acme.com")
    db.add(SensorHeartbeat(tenant_id=tid, actor="sam@acme.com", plane="ai-usage", client="palivane-hook", tool="claude-code"))
    db.commit()
    d = raw_client.get("/api/my/record", headers=h).json()
    c = d["captured"]
    assert c["findings"] == 2 and c["all_time"] == 2
    assert set(c["by_category"]) >= {"secret_leak"} and "claude-code" in c["by_tool"]
    assert c["stopped"] + c["recorded"] == 2
    assert d["sensors"][0]["client"] == "palivane-hook" and d["sensors"][0]["plane"] == "ai-usage"
    assert d["left_the_org"]["total"] == 1 and d["left_the_org"]["items"][0]["classes"]
    # The stored-text statement follows the tenant's setting.
    assert d["stored"]["content"] == bool(settings.store_content)
    t = db.get(Tenant, tid); t.store_content = True; t.retention_days = 30; db.commit()
    d2 = raw_client.get("/api/my/record", headers=h).json()
    assert d2["stored"]["content"] is True and "30 days" in d2["stored"]["how_long"]


def test_record_shows_an_active_containment(client, raw_client, db_factory):
    db = db_factory()
    h = _member(raw_client, db)
    client.post("/api/containments", json={"scope": "user", "target": "sam@acme.com", "reason": "pending review", "hours": 2})
    d = raw_client.get("/api/my/record", headers=h).json()
    assert d["contained"] and d["contained"]["scope"] == "user" and d["contained"]["reason"] == "pending review"


def test_export_is_a_file_with_my_findings_and_is_audited(client, raw_client, db_factory, monkeypatch):
    monkeypatch.setattr(settings, "gateway_enforce_secrets", False)
    db = db_factory()
    tid = _tenant(db).id
    h = _member(raw_client, db)
    _event(db, tid, f"try {AWS}", "sam@acme.com")
    _event(db, tid, f"try {AWS} too", "other@acme.com")
    r = raw_client.get("/api/my/record/export", headers=h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    assert 'filename="palivane-record-sam-at-acme.com-' in r.headers["content-disposition"]
    body = json.loads(r.content)
    assert len(body["findings"]) == 1 and body["findings"][0]["sender"] == "sam@acme.com"
    assert AWS not in r.content.decode(), "an export never carries a matched value"
    assert "content" not in body["findings"][0], "summaries only, never the stored prose"
    pulled = db_factory().query(AuditLog).filter(AuditLog.action == "record.export").all()
    assert len(pulled) == 1 and pulled[0].actor == "sam@acme.com" and pulled[0].target == "sam@acme.com"


def test_record_requires_a_session(raw_client):
    assert raw_client.get("/api/my/record").status_code in (401, 403)
    assert raw_client.get("/api/my/record/export").status_code in (401, 403)
