"""The public demo's data is moved forward to "now", so its dashboard isn't empty.

Prod seeds the demo once; two months later "See the live demo" opened on a 24h view reading zero
everywhere. refresh_clock() shifts the demo org's timestamps so its newest finding is now,
keeping the spacing between records, and never touches credentials or other orgs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import demo
from app import users as users_cli
from app.config import settings
from app.models import ApiKey, Finding, SensorHeartbeat


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def aged(db_factory, monkeypatch):
    """A demo org whose data is 60 days old, and an ordinary org with old data too."""
    monkeypatch.setattr(settings, "demo_org", "demo")
    db = db_factory()
    d = users_cli.create_tenant(db, "demo", "Demo", plan="enterprise")
    o = users_cli.create_tenant(db, "other", "Other", plan="team")
    old = _now() - timedelta(days=60)
    db.add_all([
        Finding(tenant_id=d.id, created_at=old, severity="high", sender="a@demo.local"),
        Finding(tenant_id=d.id, created_at=old - timedelta(days=3), severity="low",
                sender="b@demo.local"),
        SensorHeartbeat(tenant_id=d.id, actor="a@demo.local", plane="ai-usage",
                        first_seen=old - timedelta(days=10), last_seen=old),
        ApiKey(tenant_id=d.id, label="k", prefix="ak_x", token_hash="h",
               created_at=old, expires_at=old + timedelta(days=1)),
        Finding(tenant_id=o.id, created_at=old, severity="high", sender="c@other.io"),
    ])
    db.commit()
    yield db, d.id, o.id, old
    db.close()


def test_newest_finding_becomes_now_and_spacing_is_kept(aged):
    db, demo_id, _, _ = aged
    assert demo.refresh_clock(db) > 0
    db.expire_all()
    times = sorted(f.created_at for f in db.query(Finding).filter(Finding.tenant_id == demo_id))
    assert abs((times[-1] - _now()).total_seconds()) < 60
    assert times[-1] - times[0] == timedelta(days=3)            # relative spacing unchanged
    hb = db.query(SensorHeartbeat).filter(SensorHeartbeat.tenant_id == demo_id).one()
    assert abs((hb.last_seen - _now()).total_seconds()) < 60    # coverage panel shows activity


def test_credentials_and_other_orgs_are_not_moved(aged):
    db, demo_id, other_id, old = aged
    demo.refresh_clock(db)
    db.expire_all()
    key = db.query(ApiKey).filter(ApiKey.tenant_id == demo_id).one()
    assert key.expires_at == old + timedelta(days=1)            # no extended key lifetime
    assert key.created_at == old
    other = db.query(Finding).filter(Finding.tenant_id == other_id).one()
    assert other.created_at == old


def test_fresh_data_is_left_alone(aged):
    db, _, _, _ = aged
    demo.refresh_clock(db)
    assert demo.refresh_clock(db) == 0                          # already current: no-op


def test_no_demo_configured_is_a_no_op(aged, monkeypatch):
    db, demo_id, _, old = aged
    monkeypatch.setattr(settings, "demo_org", "")
    assert demo.refresh_clock(db) == 0
    db.expire_all()
    assert max(f.created_at for f in db.query(Finding).filter(Finding.tenant_id == demo_id)) == old
