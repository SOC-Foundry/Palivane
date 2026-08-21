"""Trial lifecycle: staged expiry-warning emails (app/trial.py) and the in-console
upgrade-request path (POST/GET /api/plans/upgrade + the operator queue)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

import app.email as email_mod
import app.trial as trial_mod
from app import users as users_cli
from app.main import app
from app.models import Tenant, UpgradeRequest

NOW = datetime(2026, 7, 29, 12, 0, 0)


def _enable_email(monkeypatch):
    sent = []
    monkeypatch.setattr(email_mod.settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(email_mod.settings, "mail_from", "palivane@test")
    monkeypatch.setattr(trial_mod.email_mod, "send",
                        lambda to, subject, body: sent.append((to, subject, body)))
    return sent


def _trial_tenant(db, days_left: float, slug: str = "trialco") -> int:
    users_cli.create_tenant(db, slug, slug.title(), plan="trial")
    users_cli.create_user(db, slug, f"admin@{slug}.com", "password123", "admin")
    t = db.query(Tenant).filter(Tenant.slug == slug).one()
    t.trial_ends_at = NOW + timedelta(days=days_left)
    db.commit()
    return t.id


def _notice(db) -> str:
    return db.query(Tenant).filter(Tenant.slug == "trialco").one().trial_notice or ""


def test_no_notice_early_in_trial(db_factory, monkeypatch):
    db = db_factory()
    sent = _enable_email(monkeypatch)
    _trial_tenant(db, days_left=10)
    assert trial_mod.run_notices(db, now=NOW) == 0
    assert sent == [] and _notice(db) == ""


@pytest.mark.parametrize("days_left,stage,expect", [
    (6.5, "d7", "ends in 7 days"),
    (1.5, "d2", "ends in 2 days"),
    (-0.5, "expired", "has ended"),
])
def test_notice_stages(db_factory, monkeypatch, days_left, stage, expect):
    db = db_factory()
    sent = _enable_email(monkeypatch)
    _trial_tenant(db, days_left=days_left)
    assert trial_mod.run_notices(db, now=NOW) == 1
    assert len(sent) == 1
    to, subject, body = sent[0]
    assert to == "admin@trialco.com" and expect in subject
    assert _notice(db) == stage
    # idempotent: the same tick never re-sends
    assert trial_mod.run_notices(db, now=NOW) == 0 and len(sent) == 1


def test_only_current_stage_sent_no_backlog(db_factory, monkeypatch):
    # A tenant that sailed past d7 and d2 unnoticed (e.g. SMTP was off) gets ONE email —
    # the stage currently due — not a backlog of three.
    db = db_factory()
    sent = _enable_email(monkeypatch)
    _trial_tenant(db, days_left=-1)
    assert trial_mod.run_notices(db, now=NOW) == 1
    assert len(sent) == 1 and "has ended" in sent[0][1]
    assert _notice(db) == "expired"


def test_stages_progress_as_clock_runs(db_factory, monkeypatch):
    db = db_factory()
    sent = _enable_email(monkeypatch)
    _trial_tenant(db, days_left=6)
    assert trial_mod.run_notices(db, now=NOW) == 1            # d7
    assert trial_mod.run_notices(db, now=NOW + timedelta(days=5)) == 1   # d2
    assert trial_mod.run_notices(db, now=NOW + timedelta(days=7)) == 1   # expired
    assert [s[1] for s in sent] == [
        "Your Palivane trial for Trialco ends in 6 days",
        "Your Palivane trial for Trialco ends in 1 day",
        "Your Palivane trial for Trialco has ended",
    ]


def test_all_admins_get_it_analysts_do_not(db_factory, monkeypatch):
    db = db_factory()
    sent = _enable_email(monkeypatch)
    _trial_tenant(db, days_left=1)
    users_cli.create_user(db, "trialco", "admin2@trialco.com", "password123", "admin")
    users_cli.create_user(db, "trialco", "analyst@trialco.com", "password123", "analyst")
    trial_mod.run_notices(db, now=NOW)
    assert sorted(s[0] for s in sent) == ["admin2@trialco.com", "admin@trialco.com"]


def test_disabled_email_sends_and_marks_nothing(db_factory):
    # Email-less deployments degrade: nothing sent, nothing marked — so notices can start
    # (from the currently due stage) if SMTP is configured later.
    db = db_factory()
    _trial_tenant(db, days_left=1)
    assert trial_mod.run_notices(db, now=NOW) == 0
    assert _notice(db) == ""


def test_non_trial_and_suspended_tenants_skipped(db_factory, monkeypatch):
    db = db_factory()
    sent = _enable_email(monkeypatch)
    tid = _trial_tenant(db, days_left=-1)
    users_cli.create_tenant(db, "teamco", "Teamco", plan="team")
    db.query(Tenant).filter(Tenant.id == tid).update({Tenant.status: "suspended"})
    db.commit()
    assert trial_mod.run_notices(db, now=NOW) == 0 and sent == []


# --- In-console upgrade path -----------------------------------------------------------

def _login(email: str) -> TestClient:
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": "password123"})
    assert r.status_code == 200, r.text
    c.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})
    return c


def test_upgrade_request_roundtrip(db_factory):
    db = db_factory()
    _trial_tenant(db, days_left=3)
    c = _login("admin@trialco.com")
    assert c.get("/api/plans/upgrade").json()["request"] is None
    r = c.post("/api/plans/upgrade", json={"plan": "team", "seats": 25, "note": "pilot went well"})
    assert r.status_code == 200, r.text
    req = r.json()["request"]
    assert req["plan"] == "team" and req["seats"] == 25 and req["status"] == "pending"
    assert req["contact"] == "admin@trialco.com"
    # visible on GET, and a duplicate while pending is refused
    assert c.get("/api/plans/upgrade").json()["request"]["id"] == req["id"]
    assert c.post("/api/plans/upgrade", json={"plan": "enterprise"}).status_code == 409
    # recorded in the org's audit log
    log = c.get("/api/audit").json()
    assert any(e["action"] == "upgrade_request" for e in log["entries"])


def test_upgrade_request_validates_plan_and_role(db_factory):
    db = db_factory()
    _trial_tenant(db, days_left=3)
    users_cli.create_user(db, "trialco", "analyst@trialco.com", "password123", "analyst")
    admin = _login("admin@trialco.com")
    assert admin.post("/api/plans/upgrade", json={"plan": "trial"}).status_code == 400
    assert admin.post("/api/plans/upgrade", json={"plan": "free"}).status_code == 400
    analyst = _login("analyst@trialco.com")
    assert analyst.post("/api/plans/upgrade", json={"plan": "team"}).status_code == 403
    assert analyst.get("/api/plans/upgrade").status_code == 403


def test_expired_trial_can_still_request_upgrade(db_factory):
    # The whole point of the path: a lapsed trial's admin must be able to buy their way out.
    db = db_factory()
    _trial_tenant(db, days_left=-1)
    c = _login("admin@trialco.com")
    assert c.post("/api/plans/upgrade", json={"plan": "team"}).status_code == 200


def test_operator_queue_and_close(db_factory, monkeypatch):
    from app import main
    monkeypatch.setattr(main.settings, "metrics_token", "op-secret")
    db = db_factory()
    _trial_tenant(db, days_left=3)
    _login("admin@trialco.com").post("/api/plans/upgrade", json={"plan": "enterprise"})

    op = TestClient(app)
    # tenant sessions must not reach the operator queue; wrong/absent token 401s
    assert op.get("/api/admin/upgrade-requests").status_code == 401
    op.headers.update({"Authorization": "Bearer op-secret"})
    rows = op.get("/api/admin/upgrade-requests").json()["requests"]
    assert len(rows) == 1 and rows[0]["slug"] == "trialco" and rows[0]["plan"] == "enterprise"

    closed = op.post(f"/api/admin/upgrade-requests/{rows[0]['id']}/close")
    assert closed.status_code == 200 and closed.json()["status"] == "closed"
    # once closed, the org may file a fresh request
    c = _login("admin@trialco.com")
    assert c.post("/api/plans/upgrade", json={"plan": "team"}).status_code == 200
    db2 = db_factory()
    assert db2.query(UpgradeRequest).count() == 2
