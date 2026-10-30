"""Scheduled-job fixes from the deep QA (M6 retention, M11 weekly report)."""

from __future__ import annotations

from datetime import datetime, timedelta

from app import alerts
from app import email as email_mod
from app.lifecycle import apply_retention
from app.models import AuditLog, Finding, Tenant


def _acme(db):
    return db.query(Tenant).filter(Tenant.slug == "acme").one()


# --- M6: retention runs on its own ---------------------------------------------------------

def test_retention_is_applied_without_the_purge_button(client, db_factory):
    db = db_factory()
    try:
        t = _acme(db)
        t.retention_days = 30
        now = datetime.utcnow()
        old = Finding(tenant_id=t.id, fingerprint="old", subject="old",
                      created_at=now - timedelta(days=31))
        new = Finding(tenant_id=t.id, fingerprint="new", subject="new",
                      created_at=now - timedelta(days=29))
        db.add_all([old, new]); db.commit()
        old_id, new_id = old.id, new.id
        assert apply_retention(db, now) >= 1
        assert db.get(Finding, old_id) is None and db.get(Finding, new_id) is not None
        assert db.query(AuditLog).filter(AuditLog.action == "findings.retention",
                                         AuditLog.actor == "system").count() == 1
    finally:
        db.close()


def test_keep_forever_is_left_alone(client, db_factory):
    db = db_factory()
    try:
        t = _acme(db)
        t.retention_days = 0
        f = Finding(tenant_id=t.id, fingerprint="ancient", subject="x",
                    created_at=datetime.utcnow() - timedelta(days=4000))
        db.add(f); db.commit()
        apply_retention(db)
        assert db.get(Finding, f.id) is not None
    finally:
        db.close()


def test_manual_purge_still_works(client, db_factory):
    db = db_factory()
    t = _acme(db)
    t.retention_days = 10
    db.add(Finding(tenant_id=t.id, fingerprint="p", subject="p",
                   created_at=datetime.utcnow() - timedelta(days=11)))
    db.commit(); db.close()
    r = client.post("/api/findings/purge").json()
    assert r["retention_days"] == 10 and r["deleted"] >= 1


# --- M11: a week is marked sent only when a mail went out ----------------------------------

def _opt_in(db_factory):
    db = db_factory()
    t = _acme(db)
    t.weekly_report, t.weekly_report_last = True, None
    db.commit(); db.close()


def _last(db_factory):
    db = db_factory()
    try:
        return _acme(db).weekly_report_last
    finally:
        db.close()


def test_failed_delivery_leaves_the_week_unsent(client, db_factory, monkeypatch):
    _opt_in(db_factory)
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "_send_sync", lambda *a: False)     # provider refused
    db = db_factory()
    try:
        assert alerts.run_weekly_reports(db) == 0
    finally:
        db.close()
    assert _last(db_factory) is None                                    # retried next tick


def test_delivered_week_is_marked_sent(client, db_factory, monkeypatch):
    _opt_in(db_factory)
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    sent = []
    monkeypatch.setattr(email_mod, "_send_sync", lambda to, *a: sent.append(to) or True)
    db = db_factory()
    try:
        assert alerts.run_weekly_reports(db) == 1
    finally:
        db.close()
    assert sent and _last(db_factory) is not None


def test_email_off_claims_nothing(client, db_factory, monkeypatch):
    _opt_in(db_factory)
    monkeypatch.setattr(email_mod, "enabled", lambda: False)
    db = db_factory()
    try:
        assert alerts.run_weekly_reports(db) == 0
    finally:
        db.close()
    assert _last(db_factory) is None
