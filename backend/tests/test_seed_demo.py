"""The demo org: a month of triage behind the open queue, so the review trail, the precision readout and
the allowlist have something to show.

These pin the SHAPE of the story the demo tells (which checks read healthy, which say "allow it", which
have too few reviews to judge, what is not counted) rather than its counts, and that nothing in it is a
state the product could not produce: a review dated before the finding, a dismissed critical finding
that kept firing (the product reopens it), an allowlist entry an admin could not have entered, or one
that does not do what its story says. A demo that contradicts the product is worse than an empty one."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.alerts as alerts
from app import allowlist, precision, seed, seed_history, seed_org, service
from app.database import Base
from app.detectors import AnalysisInput
from app.engine import engine
from app.models import AllowEntry, Finding, Tenant
from app.review import REASONS, VIAS

COUNTED = ("act", "exp", "risk", "fp", "none")      # outcomes the readout turns into rates


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    """One seeded database for the read-only tests (the seed is the slow part)."""
    path = tmp_path_factory.mktemp("seed") / "demo.db"
    eng = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    now = _now()
    seed.populate(db, now=now)
    tenant = db.query(Tenant).filter(Tenant.slug == seed.DEMO_SLUG).one()
    yield db, tenant, now
    db.close()
    eng.dispose()


def _rows(db, tenant):
    return db.query(Finding).filter(Finding.tenant_id == tenant.id).order_by(Finding.id).all()


# --- the open queue is what it was ----------------------------------------------------------------

def test_the_open_queue_is_untouched_and_stored_as_before(demo):
    db, tenant, now = demo
    queue = [f for f in _rows(db, tenant) if f.created_at == now]
    assert len(queue) == len(seed.SAMPLES)
    assert all(f.status == "open" and f.reviewed_at is None and not f.review_via for f in queue)
    first = queue[0]                          # the jailbreak sample: a masked excerpt is stored with it
    assert first.evidence_context
    pii = next(f for f in queue if "SSN 123-45-6789" in seed.SAMPLES[queue.index(f)]["content"])
    assert "123-45-6789" not in pii.content   # content is stored redacted, as before the history existed


def test_running_the_seed_again_starts_from_the_same_place(demo):
    db, tenant, now = demo
    before = (len(_rows(db, tenant)), db.query(AllowEntry).filter(AllowEntry.tenant_id == tenant.id).count())
    seed.populate(db, now=now)
    after = (len(_rows(db, tenant)), db.query(AllowEntry).filter(AllowEntry.tenant_id == tenant.id).count())
    findings = (len(seed.SAMPLES) + len(seed_history.HISTORY) + len(seed_org.LEAKS) + len(seed_org.A2A))
    assert before == after == (findings, len(seed_history.ALLOW))


# --- every row is a state the product can produce --------------------------------------------------

def test_every_review_is_internally_consistent(demo):
    db, tenant, now = demo
    for f in _rows(db, tenant):
        assert f.status in ("open", "triaged", "dismissed")
        assert f.created_at <= f.last_seen <= now and (f.seen_count or 1) >= 1
        if f.reviewed_at is None:
            assert not (f.reviewed_by or f.review_via or f.review_reason)
            continue
        assert f.status in ("triaged", "dismissed")
        assert f.created_at <= f.reviewed_at <= now
        assert f.reviewed_by == seed.DEMO_ADMIN_EMAIL and f.review_via in VIAS
        assert f.review_reason in ("", *REASONS)
        if f.status == "triaged" or f.review_via == "bulk":
            assert f.review_reason == ""      # only a person's dismissal carries a reason


def test_a_dismissed_finding_only_keeps_firing_where_the_product_lets_it(demo):
    """A dismissed finding is reopened when it recurs at high or critical severity on a live surface
    (service.py), so one that fired after its dismissal must be lower severity or an at-rest scan."""
    db, tenant, now = demo
    fired_after = [f for f in _rows(db, tenant)
                   if f.status == "dismissed" and f.reviewed_at and f.last_seen > f.reviewed_at]
    assert fired_after, "the demo should have at least one dismissed finding that keeps firing"
    for f in fired_after:
        assert not (f.severity in ("high", "critical") and any(
            s.value == f.surface for s in service._LIVE_ACT_SURFACES)), f.subject


def test_answers_from_owners_and_reviews_from_before_tracking_are_not_reviews(demo):
    db, tenant, now = demo
    answered = [f for f in _rows(db, tenant) if f.owner_response]
    assert len(answered) == sum(h["outcome"] == "owner" for h in seed_history.HISTORY)
    for f in answered:
        assert f.status == "triaged" and f.reviewed_at is None
        assert f.owner_response["action"] in ("fixed", "not_mine", "approved") and f.owner_response["note"]
    old = [f for f in _rows(db, tenant) if f.status != "open" and f.reviewed_at is None and not f.owner_response]
    assert len(old) == sum(h["outcome"].startswith("old_") for h in seed_history.HISTORY)


def test_everything_in_the_history_is_something_the_engine_flags(demo):
    """The history is scored by the real engine. If a rule stops flagging an example, the story built
    on it is no longer true, and this says which row."""
    db, tenant, now = demo
    for f, h in zip(_rows(db, tenant)[len(seed.SAMPLES):], seed_history.HISTORY):
        assert f.severity != "benign" and f.recommended_action != "allow", (h["outcome"], f.subject, f.content[:60])
        assert f.signals, f.subject


# --- the readout tells the intended story ----------------------------------------------------------

def test_the_readout_tells_the_intended_story(demo):
    db, tenant, now = demo
    r = precision.readout(db, tenant.id, 30, now)
    verdict = {c["check"]: c["verdict"] for c in r["checks"]}
    assert verdict["secret_leak"] == verdict["pii_exposure"] == "ok"          # the core checks are right
    assert verdict["sensitive_resource_access"] == "expected"                 # allow the fixtures
    assert verdict["dangerous_command"] == "mixed"
    assert verdict["prompt_injection"] == verdict["data_exfiltration"] == "low_sample"
    rv = r["reviewed"]
    assert rv["judged"] == sum(h["outcome"] in COUNTED for h in seed_history.HISTORY)
    for bucket in precision.BUCKETS:           # the legend has something in every colour
        assert rv[bucket] > 0, bucket
    assert rv["actionable_rate"] is not None and rv["correct_low"] < rv["correct_high"]   # "no reason" is a range


def test_the_readout_is_honest_about_what_it_does_not_count(demo):
    db, tenant, now = demo
    r = precision.readout(db, tenant.id, 30, now)
    assert r["bulk"]["findings"] == sum(h["outcome"] == "bulk" for h in seed_history.HISTORY) > 0
    assert r["not_counted"]["answered_by_owner"] == sum(h["outcome"] == "owner" for h in seed_history.HISTORY) > 0
    assert r["not_counted"]["before_tracking"] == sum(h["outcome"].startswith("old_") for h in seed_history.HISTORY) > 0
    assert r["backlog"]["open"] >= len(seed.SAMPLES) and r["backlog"]["oldest_open_days"] >= 30
    assert [n["reason"] for n in r["recurring_noise"]] == ["false_positive", "false_positive"]
    assert sum(1 for w in r["trend"] if w["findings"]) >= 4                   # a chart, not a single bar


# --- the allowlist, in every state -----------------------------------------------------------------

def _entries(db, tenant):
    return db.query(AllowEntry).filter(AllowEntry.tenant_id == tenant.id).order_by(AllowEntry.id).all()


def test_every_entry_is_one_an_admin_could_have_written(demo):
    db, tenant, now = demo
    for e in _entries(db, tenant):
        assert allowlist.validate(e.kind, e.pattern) == e.pattern, e.pattern
        assert len(e.reason) >= 3 and e.created_by == seed.DEMO_ADMIN_EMAIL
        assert e.created_at <= now and (e.hit_count > 0) == (e.last_hit_at is not None)
        assert (e.expires_at - e.created_at).days <= 365
        if e.finding_id:
            assert db.get(Finding, e.finding_id).tenant_id == tenant.id
        assert bool(e.revoked_at) == bool(e.revoked_by)


def test_the_allowlist_is_shown_in_every_state(demo):
    db, tenant, now = demo
    states = {e.status(now) for e in _entries(db, tenant)}
    assert states == {"active", "expired", "revoked"}
    soon = allowlist.expiring_soon(db, tenant.id, now)
    assert [(e.pattern, e.hit_count) for e in soon] == [(seed_history.UPLOADS, 0)]        # about to lapse, never used
    assert [e.pattern for e in allowlist.recently_lapsed(db, tenant.id, now)] == [seed_history.BOOTSTRAP]
    assert any(e.hit_count >= 10 for e in _entries(db, tenant) if e.status(now) == "active")


def test_the_allowlist_entries_were_made_from_the_findings_the_story_says(demo):
    db, tenant, now = demo
    by_pattern = {e.pattern: e for e in _entries(db, tenant)}
    installer = db.get(Finding, by_pattern[seed_history.INSTALLER].finding_id)
    assert installer.status == "dismissed" and installer.review_reason == "expected"
    assert installer.sender == "dana@demo.local" and installer.severity == "critical"
    fixtures = db.get(Finding, by_pattern[seed_history.FIXTURES].finding_id)
    assert fixtures.status == "dismissed" and "service-account.json" in fixtures.subject + fixtures.content
    bootstrap = db.get(Finding, by_pattern[seed_history.BOOTSTRAP].finding_id)
    assert bootstrap.status == "open"         # it lapsed, the command ran again, and that reopened it


def _signals(db, tenant, event, actor, allow):
    md = dict(event.get("metadata", {}))
    if allow:
        allowlist.attach(db, tenant.id, actor, md.get("tool", ""), md)
    item = AnalysisInput(content=event["content"], subject=event["subject"], sender=actor,
                         channel=event["channel"], surface=event["surface"], metadata=md)
    return {s["category"] for s in engine.analyze(item).to_dict()["signals"]}


def _events(content_prefix):
    return [h["event"] for h in seed_history.HISTORY if h["event"]["content"].startswith(content_prefix)]


def test_each_entry_silences_what_its_story_says_and_no_more(demo):
    db, tenant, now = demo
    installer = _events(seed_history.INSTALLER)
    assert len(installer) == 2                                       # two people ran the team's installer
    for ev in installer:
        assert "dangerous_command" in _signals(db, tenant, ev, ev["sender"], allow=False)
        assert "dangerous_command" not in _signals(db, tenant, ev, ev["sender"], allow=True)

    fixtures = [h["event"] for h in seed_history.HISTORY
                if h["outcome"] == "exp" and "/srv/northgate/testdata/" in h["event"]["content"]]
    assert len(fixtures) == 4
    for ev in fixtures:                                              # the glob covers the whole directory
        assert "sensitive_resource_access" in _signals(db, tenant, ev, ev["sender"], allow=False)
        assert "sensitive_resource_access" not in _signals(db, tenant, ev, ev["sender"], allow=True)

    other_path = {**fixtures[0], "content": "cat /srv/northgate/app/.env", "metadata": {
        **fixtures[0].get("metadata", {}), "args_text": "cat /srv/northgate/app/.env"}}
    other_path["metadata"].pop("resource", None)
    assert "sensitive_resource_access" in _signals(db, tenant, other_path, "sam@demo.local", allow=True)

    sam, other = (next(h["event"] for h in seed_history.HISTORY
                       if h["event"]["content"] == seed_history.UPLOADS and h["event"]["sender"] == who)
                  for who in ("sam@demo.local", "contractor@demo.local"))
    assert "dangerous_command" not in _signals(db, tenant, sam, sam["sender"], allow=True)   # the entry names sam
    assert "dangerous_command" in _signals(db, tenant, other, other["sender"], allow=True)   # and only sam

    bootstrap = _events(seed_history.BOOTSTRAP)[0]                   # lapsed: flagged again
    assert "dangerous_command" in _signals(db, tenant, bootstrap, bootstrap["sender"], allow=True)


def test_a_lapsed_or_revoked_entry_applies_to_nothing(demo):
    db, tenant, now = demo
    live = {e.pattern for e in allowlist.active_entries(db, tenant.id, seed.DEMO_ADMIN_EMAIL, "")}
    assert seed_history.BOOTSTRAP not in live and seed_history.STAGING_SECRETS not in live
    assert {seed_history.INSTALLER, seed_history.FIXTURES} <= live


# --- what the weekly email makes of it -------------------------------------------------------------

def test_the_weekly_email_has_something_to_say_about_the_demo_org(demo):
    db, tenant, now = demo
    text = "\n".join(alerts._quality_lines(db, tenant, now))
    assert "Detection quality (last 7 days)" in text and "closed in bulk" in text
    assert "Allowlist" in text and "never used" in text and seed_history.UPLOADS in text
    assert "flagged again" in text and seed_history.BOOTSTRAP in text
    assert seed_history.INSTALLER not in text and seed_history.STAGING_SECRETS not in text   # healthy and revoked: not news
