"""Audit-trail retention and forgetting long-dark sensors (lifecycle.prune_*)."""

from datetime import datetime, timedelta

from app.config import settings
from app.lifecycle import prune_audit_log, prune_dark_sensors
from app.models import AuditLog, SensorHeartbeat, Tenant

NOW = datetime(2026, 11, 1, 12, 0, 0)


def _tenant(db):
    t = Tenant(slug="acme", name="Acme")
    db.add(t)
    db.commit()
    return t


def test_audit_log_prunes_only_past_retention(db_factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_retention_days", 730)
    db = db_factory()
    t = _tenant(db)
    for days in (10, 729, 731, 2000):
        db.add(AuditLog(tenant_id=t.id, action=f"age.{days}",
                        created_at=NOW - timedelta(days=days)))
    db.commit()

    assert prune_audit_log(db, now=NOW) == 2
    assert sorted(a.action for a in db.query(AuditLog)) == ["age.10", "age.729"]


def test_audit_log_zero_keeps_forever(db_factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_retention_days", 0)
    db = db_factory()
    t = _tenant(db)
    db.add(AuditLog(tenant_id=t.id, action="ancient", created_at=NOW - timedelta(days=5000)))
    db.commit()

    assert prune_audit_log(db, now=NOW) == 0
    assert db.query(AuditLog).count() == 1


def test_dark_sensors_forgotten_after_threshold(db_factory, monkeypatch):
    monkeypatch.setattr(settings, "sensor_forget_days", 90)
    db = db_factory()
    t = _tenant(db)
    # 4 days dark is exactly what the fleet view and the 72h dark alert exist for: kept.
    for days in (0, 4, 89, 91, 400):
        db.add(SensorHeartbeat(tenant_id=t.id, actor=f"dev{days}", plane="ai-usage",
                               last_seen=NOW - timedelta(days=days)))
    db.commit()

    assert prune_dark_sensors(db, now=NOW) == 2
    assert sorted(h.actor for h in db.query(SensorHeartbeat)) == ["dev0", "dev4", "dev89"]


def test_dark_sensors_zero_never_forgets(db_factory, monkeypatch):
    monkeypatch.setattr(settings, "sensor_forget_days", 0)
    db = db_factory()
    t = _tenant(db)
    db.add(SensorHeartbeat(tenant_id=t.id, actor="old", last_seen=NOW - timedelta(days=900)))
    db.commit()

    assert prune_dark_sensors(db, now=NOW) == 0
    assert db.query(SensorHeartbeat).count() == 1
