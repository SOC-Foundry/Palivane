"""Fleet alerts: gone-dark sensors and dead keys page the tenant webhook, edge-triggered."""

from __future__ import annotations

from datetime import datetime, timedelta

import app.alerts as alerts
from app.models import ApiKey, SensorHeartbeat, Tenant


def _setup(db_factory, webhook="https://hooks.example/x"):
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").first()
    t.alert_webhook = webhook
    db.commit()
    tid = t.id
    db.close()
    return tid


def _hb(db_factory, tid, actor, hours_ago, plane="ai-usage", tool="claude.ai"):
    db = db_factory()
    db.add(SensorHeartbeat(tenant_id=tid, actor=actor, plane=plane, tool=tool,
                           last_seen=datetime.utcnow() - timedelta(hours=hours_ago)))
    db.commit()
    db.close()


def test_dark_sensor_alerts_once(client, db_factory, monkeypatch):
    tid = _setup(db_factory)
    _hb(db_factory, tid, "alice@acme.com", hours_ago=100)   # dark
    _hb(db_factory, tid, "bob@acme.com", hours_ago=1)       # fresh
    posts = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, timeout=8.0:
                        posts.append((url, payload)) or True)
    db = db_factory()
    assert alerts.run_fleet_alerts(db) == 1
    # edge-triggered: the next sweep is silent
    assert alerts.run_fleet_alerts(db) == 0
    db.close()
    assert len(posts) == 1
    text = posts[0][1]["text"]
    assert "alice@acme.com" in text and "bob@acme.com" not in text
    assert posts[0][1]["palivane"]["event"] == "fleet_health"


def test_resumed_sensor_rearms(client, db_factory, monkeypatch):
    tid = _setup(db_factory)
    _hb(db_factory, tid, "carol@acme.com", hours_ago=100)
    monkeypatch.setattr(alerts, "send_sync", lambda *a, **k: True)
    db = db_factory()
    assert alerts.run_fleet_alerts(db) == 1
    db.close()
    # the sensor comes back — the capture-path upsert clears the marker
    from app.main import _record_heartbeat
    db = db_factory()
    _record_heartbeat(db, tid, "carol@acme.com", "ai-usage", "claude.ai")
    db.commit()
    row = (db.query(SensorHeartbeat)
           .filter(SensorHeartbeat.tenant_id == tid,
                   SensorHeartbeat.actor == "carol@acme.com").first())
    assert row.dark_alerted_at is None
    db.close()


def test_dead_key_alerts_once(client, db_factory, monkeypatch):
    tid = _setup(db_factory)
    db = db_factory()
    db.add(ApiKey(tenant_id=tid, label="build-laptop", prefix="ak_dead1", token_hash="x",
                  actor="ci@acme.com", active=False,
                  last_failed_at=datetime.utcnow() - timedelta(hours=2)))
    db.commit()
    db.close()
    posts = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, timeout=8.0:
                        posts.append(payload) or True)
    db = db_factory()
    assert alerts.run_fleet_alerts(db) == 1
    assert alerts.run_fleet_alerts(db) == 0
    db.close()
    assert "build-laptop" in posts[0]["text"] and "revoked key" in posts[0]["text"]


def test_no_webhook_no_alert(client, db_factory, monkeypatch):
    tid = _setup(db_factory, webhook="")
    _hb(db_factory, tid, "dave@acme.com", hours_ago=100)
    monkeypatch.setattr(alerts, "send_sync", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("must not post without a webhook")))
    db = db_factory()
    assert alerts.run_fleet_alerts(db) == 0
    db.close()
