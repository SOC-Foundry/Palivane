"""Durable SIEM/alert outbox: enqueue does not send, drain retries, a second worker
does not double-send, and a restart (a new session) still sees the row."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import alerts, outbox, siem
from app.database import Base
from app.models import DeliveryCursor, DeliveryOutbox, Tenant


def _db():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _tenant(db, **kw) -> Tenant:
    t = Tenant(slug=kw.pop("slug", "acme"), name="Acme",
               alert_webhook=kw.pop("alert_webhook", ""),
               alert_min_severity=kw.pop("alert_min_severity", "high"),
               siem_url=kw.pop("siem_url", ""),
               siem_token=kw.pop("siem_token", ""),
               siem_format=kw.pop("siem_format", "json"),
               siem_min_severity=kw.pop("siem_min_severity", "high"),
               siem_s3_bucket=kw.pop("siem_s3_bucket", ""),
               siem_s3_key_id=kw.pop("siem_s3_key_id", ""),
               siem_s3_secret=kw.pop("siem_s3_secret", ""),
               siem_s3_region=kw.pop("siem_s3_region", ""),
               siem_s3_role_arn=kw.pop("siem_s3_role_arn", ""),
               siem_s3_external_id=kw.pop("siem_s3_external_id", ""))
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


_VERDICT = {"severity": "critical", "risk_score": 90, "finding_id": 7,
            "signals": [{"category": "secret_leak"}]}


def test_enqueue_does_not_send_and_drain_does(monkeypatch):
    sent = []
    monkeypatch.setattr(siem, "send_detail", lambda *a, **k: (sent.append(a) or (True, "")))
    db = _db()
    t = _tenant(db, siem_url="https://collector.example/in", siem_token="tok")
    siem.forward("https://collector.example/in", "tok", "high", "json", _VERDICT,
                 subject="s", actor="a", surface="ai_usage", org="acme",
                 tenant_id=t.id, db=db)
    db.commit()
    assert sent == []
    assert db.query(DeliveryOutbox).filter_by(status="pending").count() == 1
    assert outbox.drain_once(db) == 1
    assert sent and sent[0][0] == "https://collector.example/in"
    row = db.query(DeliveryOutbox).one()
    assert row.status == "delivered"
    snap = outbox.snapshot(db, t.id)
    assert snap["backlog"] == 0 and snap["last_success"] and snap["by_sink"]["siem_http"]["dead"] == 0


def test_severity_and_missing_config_do_not_enqueue():
    db = _db()
    t = _tenant(db, siem_url="https://collector.example/in")
    siem.forward("https://collector.example/in", "", "high", "json",
                 {"severity": "low", "risk_score": 1, "signals": []},
                 tenant_id=t.id, db=db)
    siem.forward("", "", "high", "json", _VERDICT, tenant_id=t.id, db=db)
    db.commit()
    assert db.query(DeliveryOutbox).count() == 0


def test_failure_retries_then_dead_letters(monkeypatch):
    monkeypatch.setattr(siem, "send_detail", lambda *a, **k: (False, "HTTP Error 503"))
    monkeypatch.setattr(outbox, "MAX_ATTEMPTS", 2)
    db = _db()
    t = _tenant(db, siem_url="https://collector.example/in", siem_token="tok")
    siem.forward("https://collector.example/in", "tok", "high", "json", _VERDICT,
                 tenant_id=t.id, db=db)
    db.commit()
    assert outbox.drain_once(db) == 1
    row = db.query(DeliveryOutbox).one()
    assert row.status == "pending" and row.attempts == 1 and "503" in row.last_error
    # Not due yet: the backoff holds it.
    assert outbox.drain_once(db) == 0
    row.next_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    db.commit()
    assert outbox.drain_once(db) == 1
    db.refresh(row)
    assert row.status == "dead" and row.attempts == 2
    snap = outbox.snapshot(db, t.id)
    assert snap["dead"] == 1 and snap["backlog"] == 0 and "503" in snap["last_error"]
    cur = db.query(DeliveryCursor).one()
    assert cur.dead_count == 1 and cur.last_failure_at is not None


def test_removed_sink_is_dead_immediately(monkeypatch):
    monkeypatch.setattr(alerts, "send_result", lambda *a, **k: (True, ""))
    db = _db()
    t = _tenant(db, alert_webhook="https://hooks.example/x")
    alerts.notify("https://hooks.example/x", "high", _VERDICT, db=db, tenant_id=t.id)
    db.commit()
    t.alert_webhook = ""
    db.commit()
    outbox.drain_once(db)
    row = db.query(DeliveryOutbox).one()
    assert row.status == "dead" and row.attempts == 1
    assert "no longer configured" in row.last_error


def test_claim_is_exclusive_across_sessions(monkeypatch):
    """Two workers (two sessions) must not both send the same row."""
    calls = []
    monkeypatch.setattr(siem, "send_detail", lambda *a, **k: (calls.append(1) or (True, "")))
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    db = Session()
    t = _tenant(db, siem_url="https://collector.example/in", siem_token="tok")
    siem.forward("https://collector.example/in", "tok", "high", "json", _VERDICT,
                 tenant_id=t.id, db=db)
    db.commit()
    other = Session()
    assert outbox.drain_once(db) == 1
    assert outbox.drain_once(other) == 0
    assert calls == [1]
    other.close()
    db.close()


def test_a_new_session_sees_a_row_queued_before_restart(monkeypatch):
    """Survives a restart: the row is in the database, not in the process."""
    monkeypatch.setattr(alerts, "send_result", lambda *a, **k: (True, ""))
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    db = Session()
    t = _tenant(db, alert_webhook="https://hooks.example/x")
    alerts.notify("https://hooks.example/x", "high", _VERDICT, db=db, tenant_id=t.id)
    db.commit()
    db.close()                      # the capturing process is gone
    nxt = Session()
    assert nxt.query(DeliveryOutbox).filter_by(status="pending").count() == 1
    assert outbox.drain_once(nxt) == 1
    assert nxt.query(DeliveryOutbox).one().status == "delivered"
    nxt.close()


def test_alert_below_threshold_is_not_queued():
    db = _db()
    t = _tenant(db, alert_webhook="https://hooks.example/x")
    alerts.notify("https://hooks.example/x", "high",
                  {"severity": "low", "risk_score": 1, "signals": []},
                  db=db, tenant_id=t.id)
    alerts.notify("https://hooks.example/x", "high", _VERDICT, db=db, tenant_id=t.id)
    db.commit()
    assert db.query(DeliveryOutbox).count() == 1
