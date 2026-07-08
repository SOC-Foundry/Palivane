"""Alert digests: real-time gating + periodic rollup (run_digests)."""

from __future__ import annotations

from datetime import datetime, timedelta

from app import alerts
from app.models import Tenant, Finding


# --- real-time gating -----------------------------------------------------------------

def test_realtime_gating():
    ok = alerts._realtime_ok
    # off (real-time): anything >= min fires
    assert ok("high", "high", "off") is True
    assert ok("suspicious", "high", "off") is False        # below threshold
    # digest: only critical fires in real time; the rest is batched
    assert ok("high", "high", "daily") is False
    assert ok("critical", "high", "daily") is True
    assert ok("critical", "high", "hourly") is True


# --- run_digests ----------------------------------------------------------------------

def _mk_finding(db, tenant_id, severity, minutes_ago):
    f = Finding(tenant_id=tenant_id, surface="ai_usage", subject=f"{severity} thing",
                sender="dev@acme.com", severity=severity, risk_score=70, status="open",
                created_at=datetime.utcnow() - timedelta(minutes=minutes_ago))
    db.add(f); db.commit()
    return f


def _tenant(db):
    return db.query(Tenant).first()


def test_run_digests_batches_and_claims(client, db_factory, monkeypatch):
    # capture what would be POSTed instead of hitting the network
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)

    db = db_factory()
    t = _tenant(db)
    t.alert_webhook = "https://hooks.example.com/x"
    t.alert_min_severity = "high"
    t.alert_digest = "daily"
    t.alert_digest_last = None
    _mk_finding(db, t.id, "high", 30)
    _mk_finding(db, t.id, "critical", 20)
    _mk_finding(db, t.id, "suspicious", 10)   # below threshold -> excluded
    db.commit()

    n = alerts.run_digests(db)
    assert n == 1 and len(sent) == 1
    payload = sent[0]
    assert payload["warden"]["count"] == 2                 # high + critical, not suspicious
    assert payload["warden"]["by_severity"] == {"high": 1, "critical": 1}
    assert "digest" in payload["text"].lower()

    # window claimed -> a second run right away sends nothing
    assert alerts.run_digests(db) == 0 and len(sent) == 1
    db.close()


def test_run_digests_skips_when_off_or_no_webhook(client, db_factory, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)
    db = db_factory()
    t = _tenant(db)
    t.alert_digest = "off"; t.alert_webhook = "https://hooks.example.com/x"
    _mk_finding(db, t.id, "critical", 5)
    db.commit()
    assert alerts.run_digests(db) == 0 and sent == []      # off -> not batched
    db.close()
