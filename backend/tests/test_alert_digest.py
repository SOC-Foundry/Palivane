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
    assert payload["palivane"]["count"] == 2                 # high + critical, not suspicious
    assert payload["palivane"]["by_severity"] == {"high": 1, "critical": 1}
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


# --- recurrences must reach the digest --------------------------------------------------
#
# Recurrence folding reuses the first finding's row, so a repeat produces no new row and no
# new created_at — only `last_seen` moves. Both rollups filtered on created_at, so an event
# class was reported exactly once, in the window it first appeared, and never again however
# often it came back. The reopen change makes it worse: a dismissed finding that returns is
# the thing a digest most needs to carry, and it has an old created_at by definition.

def _recurring(db, tenant_id, severity, created_min_ago, seen_min_ago):
    f = Finding(tenant_id=tenant_id, surface="ai_usage", subject="recurring leak",
                sender="dev@acme.com", severity=severity, risk_score=90, status="open",
                seen_count=7,
                created_at=datetime.utcnow() - timedelta(minutes=created_min_ago),
                last_seen=datetime.utcnow() - timedelta(minutes=seen_min_ago))
    db.add(f); db.commit()
    return f


def test_a_recurrence_of_an_old_finding_is_in_the_digest(client, db_factory, monkeypatch):
    """Created long before the window, seen inside it. Before the fix: count 0, no send."""
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)
    db = db_factory()
    t = _tenant(db)
    t.alert_webhook = "https://hooks.example.com/x"
    t.alert_min_severity = "high"
    t.alert_digest = "hourly"
    t.alert_digest_last = datetime.utcnow() - timedelta(hours=2)
    _recurring(db, t.id, "critical", created_min_ago=60 * 24 * 30, seen_min_ago=5)
    db.commit()

    assert alerts.run_digests(db) == 1
    assert sent[0]["palivane"]["count"] == 1
    db.close()


def test_a_genuinely_quiet_finding_stays_out(client, db_factory, monkeypatch):
    """The fix must not widen the window to "everything ever recorded" — a finding that has
    not been seen since the last digest has nothing new to report."""
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)
    db = db_factory()
    t = _tenant(db)
    t.alert_webhook = "https://hooks.example.com/x"
    t.alert_min_severity = "high"
    t.alert_digest = "hourly"
    t.alert_digest_last = datetime.utcnow() - timedelta(hours=2)
    _recurring(db, t.id, "critical", created_min_ago=60 * 24 * 30, seen_min_ago=60 * 24 * 10)
    db.commit()

    assert alerts.run_digests(db) == 0 and sent == []
    db.close()


def test_a_row_predating_the_last_seen_column_still_counts(client, db_factory, monkeypatch):
    """NULL last_seen must fall back to created_at rather than dropping out — the reason the
    filter is an OR and not a coalesce."""
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)
    db = db_factory()
    t = _tenant(db)
    t.alert_webhook = "https://hooks.example.com/x"
    t.alert_min_severity = "high"
    t.alert_digest = "hourly"
    t.alert_digest_last = datetime.utcnow() - timedelta(hours=2)
    f = _mk_finding(db, t.id, "critical", 10)
    f.last_seen = None
    db.commit()

    assert alerts.run_digests(db) == 1
    assert sent[0]["palivane"]["count"] == 1
    db.close()
