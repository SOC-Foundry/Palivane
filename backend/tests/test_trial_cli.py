"""Operator-set trials get a clock, and the operator can see it.

A trial with no end date is open-ended (plans.trial_expired), so before this a trial set with
`set-plan --plan trial` never expired and never showed the console's countdown, while the
plan column kept saying "trial" long after a self-serve trial's 14 days were up.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import users as users_cli
from app.config import settings
from app.models import Tenant
from app.plans import plan_of


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def db(db_factory):
    s = db_factory()
    yield s
    s.close()


def _days_until(ends) -> float:
    return (ends - _now()).total_seconds() / 86400


def test_moving_into_trial_starts_the_configured_clock(db, monkeypatch):
    monkeypatch.setattr(settings, "trial_days", 14)
    t = users_cli.create_tenant(db, "acme", "Acme", plan="free")
    users_cli.apply_plan(t, "trial")
    assert 13.9 < _days_until(t.trial_ends_at) <= 14
    assert plan_of(t) == "trial"


def test_trial_days_sets_the_length(db):
    t = users_cli.create_tenant(db, "acme", "Acme", plan="trial", trial_days=30)
    assert 29.9 < _days_until(t.trial_ends_at) <= 30
    assert "trial ends" in users_cli.trial_note(t) and "30 days left" in users_cli.trial_note(t)


def test_rerunning_set_plan_keeps_a_running_clock(db):
    t = users_cli.create_tenant(db, "acme", "Acme", plan="trial", trial_days=5)
    ends = t.trial_ends_at
    users_cli.apply_plan(t, "trial")                 # no --trial-days: clock untouched
    assert t.trial_ends_at == ends
    users_cli.apply_plan(t, "trial", trial_days=20)  # explicit: extended from now
    assert 19.9 < _days_until(t.trial_ends_at) <= 20


def test_an_open_ended_trial_gets_a_clock_when_set_again(db, monkeypatch):
    # Orgs put on trial before this fix have no end date; setting trial again gives them one.
    monkeypatch.setattr(settings, "trial_days", 14)
    t = Tenant(slug="old", name="Old", plan="trial", trial_ends_at=None)
    db.add(t); db.commit()
    assert users_cli.trial_note(t) == "trial has no end date"
    users_cli.apply_plan(t, "trial")
    assert t.trial_ends_at is not None


def test_zero_days_is_an_open_ended_trial_on_purpose(db):
    t = users_cli.create_tenant(db, "acme", "Acme", plan="trial", trial_days=0)
    assert t.trial_ends_at is None and plan_of(t) == "trial"
    assert users_cli.trial_note(t) == "trial has no end date"


def test_an_ended_trial_reads_as_ended(db):
    t = users_cli.create_tenant(db, "acme", "Acme", plan="trial", trial_days=14)
    t.trial_ends_at = _now() - timedelta(days=3)
    assert plan_of(t) == "expired"
    assert users_cli.trial_note(t).startswith("trial ended ")


def test_other_plans_carry_no_trial_note(db):
    t = users_cli.create_tenant(db, "acme", "Acme", plan="trial", trial_days=14)
    users_cli.apply_plan(t, "team")
    assert t.plan == "team" and users_cli.trial_note(t) == ""
    assert users_cli.trial_note(users_cli.create_tenant(db, "beta", "Beta")) == ""
