"""The precision readout: how often a check is right, according to the people who reviewed it.

Two halves. Capture: every place a status changes records who decided, how and why (and a reopen
clears it), because `status` alone cannot tell a false positive from behavior the org expects, or an
analyst's call from the owner having answered. Readout: only what that record supports, with every
exclusion counted and shown, so a cleared queue cannot make every check look like noise."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app.precision as precision
from app import review
from app import users as users_cli
from app.eval.export import finding_to_example
from app.main import app
from app.models import Finding, Tenant
from fastapi.testclient import TestClient

ADMIN = "admin@acme.com"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _tid(db_factory):
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == "acme").first().id
    finally:
        db.close()


def _sig(check="dangerous_command", weight=0.9, conf=0.9, title="High-risk command in a tool call",
         evidence="tool=Bash"):
    return {"category": check, "check": check, "title": title, "detail": "", "weight": weight,
            "confidence": conf, "detector": "mcp_guard", "evidence": evidence}


def _add(db_factory, tenant_id=None, *, status="open", reason="", via="", ago_days=None, seen=1,
         signals=None, channel="Bash", sender="dev@acme.com", severity="high", owner_response=None,
         created_days_ago=0, reviewed_by="admin@acme.com"):
    """A finding row with exactly the fields the readout reads."""
    db = db_factory()
    f = Finding(tenant_id=tenant_id or _tid(db_factory), status=status, severity=severity,
                risk_score=80, surface="agent_tools", channel=channel, sender=sender,
                subject="Agent tool: Bash", seen_count=seen,
                signals=signals if signals is not None else [_sig()], owner_response=owner_response,
                created_at=_now() - timedelta(days=created_days_ago),
                last_seen=_now() - timedelta(days=created_days_ago))
    if ago_days is not None:
        f.reviewed_at = _now() - timedelta(days=ago_days)
        f.reviewed_by, f.review_via, f.review_reason = reviewed_by, via or "manual", reason
    db.add(f)
    db.commit()
    fid = f.id
    db.close()
    return fid


def _row(db_factory, fid):
    db = db_factory()
    try:
        f = db.get(Finding, fid)
        db.expunge(f)
        return f
    finally:
        db.close()


def _patch(client, fid, status, **extra):
    return client.patch(f"/api/findings/{fid}", json={"status": status, **extra})


def _readout(client, **params):
    r = client.get("/api/precision", params=params)
    assert r.status_code == 200, r.text
    return r.json()


# --- capture ---

def test_triaging_records_who_decided_and_how(client, db_factory):
    fid = _add(db_factory)
    assert _patch(client, fid, "triaged").status_code == 200
    f = _row(db_factory, fid)
    assert (f.status, f.reviewed_by, f.review_via, f.review_reason) == ("triaged", ADMIN, "manual", "")
    assert f.reviewed_at is not None and abs((_now() - f.reviewed_at).total_seconds()) < 30
    review_view = client.get(f"/api/findings/{fid}").json()["review"]
    assert review_view["by"] == ADMIN and review_view["via"] == "manual" and review_view["reason"] == ""


def test_a_dismissal_records_why_and_the_audit_trail_says_so(client, db_factory):
    fid = _add(db_factory)
    _patch(client, fid, "dismissed", reason="expected")
    assert _row(db_factory, fid).review_reason == "expected"
    assert client.get(f"/api/findings/{fid}").json()["review"]["reason"] == "expected"
    entries = client.get("/api/audit", params={"action": "finding.status"}).json()["entries"]
    assert any(e["target"] == str(fid) and e["detail"].get("reason") == "expected" for e in entries)


def test_a_reason_means_nothing_unless_the_finding_is_dismissed(client, db_factory):
    fid = _add(db_factory)
    _patch(client, fid, "triaged", reason="false_positive")
    assert _row(db_factory, fid).review_reason == ""


def test_an_unknown_reason_is_refused_and_changes_nothing(client, db_factory):
    fid = _add(db_factory)
    assert _patch(client, fid, "dismissed", reason="because").status_code == 422
    f = _row(db_factory, fid)
    assert f.status == "open" and f.reviewed_at is None


def test_the_reasons_the_api_accepts_are_the_ones_the_readout_knows():
    from app.schemas import StatusUpdate
    accepted = {r for r in StatusUpdate.model_fields["reason"].annotation.__args__ if r}
    assert accepted == set(review.REASONS)


def test_applying_the_analysts_recommendation_is_recorded_as_that(client, db_factory):
    fid = _add(db_factory)
    _patch(client, fid, "dismissed", via="analyst")
    f = _row(db_factory, fid)
    assert f.review_via == "analyst" and f.reviewed_by == ADMIN


def test_reopening_clears_the_review_so_it_is_not_counted_as_one(client, db_factory):
    fid = _add(db_factory)
    _patch(client, fid, "dismissed", reason="false_positive")
    _patch(client, fid, "open")
    f = _row(db_factory, fid)
    assert (f.status, f.reviewed_at, f.reviewed_by, f.review_via, f.review_reason) == ("open", None, "", "", "")
    assert client.get(f"/api/findings/{fid}").json()["review"] is None


def test_one_finding_is_a_manual_review_and_several_are_bulk(client, db_factory):
    a, b, c = (_add(db_factory) for _ in range(3))
    client.post("/api/findings/bulk-status", json={"ids": [a, b, c], "status": "dismissed", "reason": "expected"})
    for fid in (a, b, c):
        f = _row(db_factory, fid)
        assert (f.review_via, f.review_reason, f.reviewed_by) == ("bulk", "expected", ADMIN)
    solo = _add(db_factory)
    client.post("/api/findings/bulk-status", json={"ids": [solo], "status": "triaged"})
    assert _row(db_factory, solo).review_via == "manual"
    client.post("/api/findings/bulk-status", json={"ids": [a, b], "status": "open"})
    assert _row(db_factory, a).reviewed_at is None and _row(db_factory, a).review_via == ""


def test_the_benign_cleanup_is_a_bulk_action(client, db_factory):
    low = _add(db_factory, severity="low")
    client.post("/api/findings/dismiss-benign")
    f = _row(db_factory, low)
    assert f.status == "dismissed" and f.review_via == "bulk" and f.review_reason == ""


def test_the_owner_answering_is_not_a_review(client, db_factory):
    fid = _add(db_factory, sender=ADMIN)                         # this finding is the admin's own
    r = client.post(f"/api/my/findings/{fid}/respond", json={"action": "fixed", "note": "done"})
    assert r.status_code == 200 and r.json()["status"] == "triaged"
    f = _row(db_factory, fid)
    assert f.status == "triaged" and f.reviewed_at is None and f.review_via in (None, "")


def test_a_recurrence_that_reopens_a_dismissed_finding_clears_its_review(client, db_factory):
    key = client.post("/api/apikeys", json={"label": "k", "actor": "dev@acme.com"}).json()["token"]
    prompt = "Please summarize the claim for Maria Lopez, SSN 457-55-5462, and email her about the denial."
    post = lambda: client.post("/api/ingest/ai-usage", json={"content": prompt, "destination": "https://chatgpt.com/",
                                                              "tool": "chatgpt"}, headers={"X-Palivane-Token": key}).json()
    first = post()
    _patch(client, first["finding_id"], "dismissed", reason="false_positive")
    again = post()
    assert again["finding_id"] == first["finding_id"]                    # the same finding, folded
    f = _row(db_factory, first["finding_id"])
    assert f.status == "open" and f.reviewed_at is None and f.review_reason == ""


def test_an_analyst_who_triages_is_recorded_by_name(client, db_factory):
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    c = TestClient(app)
    tok = c.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {tok}"})
    fid = _add(db_factory)
    assert _patch(c, fid, "triaged").status_code == 200
    assert _row(db_factory, fid).reviewed_by == "analyst@acme.com"
    assert _patch(c, fid, "dismissed", reason="expected").status_code == 403          # still admin only


# --- the arithmetic ---

@pytest.mark.parametrize("status,reason,expected", [
    ("triaged", "", "actionable"), ("triaged", "false_positive", "actionable"),
    ("dismissed", "expected", "expected"), ("dismissed", "accepted_risk", "expected"),
    ("dismissed", "false_positive", "false_positive"), ("dismissed", "duplicate", "duplicate"),
    ("dismissed", "", "unspecified"), ("dismissed", "nonsense", "unspecified"),
])
def test_what_each_review_counts_as(status, reason, expected):
    assert precision.bucket(status, reason) == expected


def test_the_wilson_interval():
    assert precision.wilson(0, 0) is None
    lo, hi = precision.wilson(8, 10)
    assert (lo, hi) == (0.49, 0.943)
    assert precision.wilson(10, 10)[1] == 1.0 and precision.wilson(10, 10)[0] < 1.0
    assert precision.wilson(0, 10)[0] == 0.0 and 0.2 < precision.wilson(0, 10)[1] < 0.35
    small, big = precision.wilson(3, 5), precision.wilson(60, 100)
    assert (small[1] - small[0]) > (big[1] - big[0])              # fewer reviews, wider doubt


def test_the_signal_a_review_is_credited_to():
    sigs = [_sig("unsanctioned_ai", 0.5, 0.9), _sig("secret_leak", 0.9, 0.85), _sig("pii_exposure", 0.8, 0.75)]
    assert precision.primary(sigs)[0] == "secret_leak"
    assert precision.primary([{"category": "x", "weight": 0.1, "confidence": None}])[0] == "x"   # no `check`
    assert precision.primary([{"check": "a_check", "category": "cat", "weight": 1}])[0] == "a_check"
    assert precision.primary([None, "junk", {}, {"category": ""}]) == ("unknown", "", "")
    assert precision.primary(None) == ("unknown", "", "")
    assert precision.primary([{"category": "x", "weight": "NaN-ish", "confidence": "y"}])[0] == "x"


def _rv(status="dismissed", reason="", via="manual", events=1, signals=None, channel="Bash", rid=1,
        reviewed_at=None, sender="dev@acme.com", last_seen=None):
    reviewed_at = reviewed_at or _now()
    return {"id": rid, "status": status, "reason": reason, "via": via, "events": events,
            "signals": signals if signals is not None else [_sig()], "channel": channel,
            "reviewed_at": reviewed_at, "sender": sender,
            "last_seen": last_seen or reviewed_at + timedelta(hours=1)}


def _compute(reviews, legacy=(), backlog=None, days=30, **kw):
    return precision.compute(list(reviews), list(legacy), backlog or {"open": 0, "open_high": 0, "oldest_open_days": None},
                             _now(), days, **kw)


def test_the_rates_say_what_the_reviews_support_and_no_more():
    reviews = ([_rv("triaged")] * 4 + [_rv(reason="expected")] + [_rv(reason="accepted_risk")]
               + [_rv(reason="false_positive")] + [_rv()] * 3 + [_rv(reason="duplicate")])
    r = _compute(reviews)["reviewed"]
    assert r["findings"] == 11 and r["judged"] == 10                      # the duplicate is not judged
    assert (r["actionable"], r["expected"], r["false_positive"], r["unspecified"], r["duplicate"]) == (4, 2, 1, 3, 1)
    assert r["actionable_rate"] == 0.4
    assert r["correct_low"] == 0.6 and r["correct_high"] == 0.9           # "no reason" could be either
    assert r["actionable_ci"][0] < 0.4 < r["actionable_ci"][1]


def test_when_every_dismissal_has_a_reason_the_range_is_a_number():
    r = _compute([_rv("triaged")] * 3 + [_rv(reason="false_positive")] * 2 + [_rv(reason="expected")])["reviewed"]
    assert r["correct_low"] == r["correct_high"] == round(4 / 6, 3)


def test_events_are_counted_beside_findings_and_noise_is_shown_by_volume():
    reviews = [_rv("triaged", events=2), _rv(reason="false_positive", events=300)]
    r = _compute(reviews)["reviewed"]
    assert (r["findings"], r["events"], r["actionable_events"], r["false_positive_events"]) == (2, 302, 2, 300)
    assert r["noise_event_share"] == round(300 / 302, 3)
    assert r["actionable_rate"] == 0.5                                    # by finding: one needed action, one did not


def test_bulk_closures_are_counted_apart_and_never_enter_a_rate():
    reviews = [_rv("triaged")] * 3 + [_rv(via="bulk", events=40)] * 50
    out = _compute(reviews)
    assert out["bulk"] == {"findings": 50, "events": 2000}
    assert out["reviewed"]["findings"] == 3 and out["reviewed"]["actionable_rate"] == 1.0
    assert out["checks"][0]["findings"] == 3 and out["trend"][-1]["findings"] <= 3


def test_what_has_no_review_record_is_reported_not_guessed():
    legacy = ([{"status": "triaged", "answered": True}] * 2 + [{"status": "triaged", "answered": False}]
              + [{"status": "dismissed", "answered": False}] * 4 + [{"status": "dismissed", "answered": True}])
    nc = _compute([], legacy)["not_counted"]
    # eight with no record: two triaged only because their owner answered, six by an unknown hand
    assert nc == {"answered_by_owner": 2, "before_tracking": 6}


def test_a_review_is_credited_to_the_one_check_that_drove_the_finding():
    sigs = [_sig("unsanctioned_ai", 0.3, 0.9, title="Unsanctioned AI tool"), _sig("secret_leak", 0.9, 0.9, title="Secret")]
    out = _compute([_rv("triaged", signals=sigs)])
    assert [c["check"] for c in out["checks"]] == ["secret_leak"] and out["checks"][0]["title"] == "Secret"
    assert out["reviewed"]["findings"] == 1
    # and that one review lands everywhere it belongs: its check, its tool and its week
    assert (out["checks"][0]["findings"], out["checks"][0]["actionable"]) == (1, 1)
    assert [(t["tool"], t["findings"]) for t in out["tools"]] == [("Bash", 1)]
    assert sum(w["findings"] for w in out["trend"]) == 1


def test_a_review_record_only_ever_holds_values_the_readout_understands():
    for via in ("hacker", "", None, "Bulk"):
        assert review.review_values("triaged", "a@b.c", via)["review_via"] == "manual"
    assert review.review_values("triaged", "a@b.c", "bulk")["review_via"] == "bulk"
    assert review.review_values("dismissed", "a@b.c", "manual", "made-up")["review_reason"] == ""
    assert review.review_values("dismissed", "a@b.c", "manual", "expected")["review_reason"] == "expected"
    assert review.review_values("open", "a@b.c", "bulk", "expected") == {
        "reviewed_at": None, "reviewed_by": "", "review_via": "", "review_reason": ""}
    assert len(review.review_values("triaged", "x" * 900)["reviewed_by"]) == 320


def test_the_checks_that_most_need_attention_come_first_and_thin_ones_last():
    reviews = ([_rv("triaged", signals=[_sig("good")])] * 8 + [_rv(signals=[_sig("good")])] * 2
               + [_rv("triaged", signals=[_sig("noisy")])] * 1 + [_rv(signals=[_sig("noisy")])] * 7
               + [_rv(signals=[_sig("thin")])] * 2)
    assert [c["check"] for c in _compute(reviews)["checks"]] == ["noisy", "good", "thin"]


@pytest.mark.parametrize("make,verdict", [
    (lambda: [_rv("triaged")] * 2, "low_sample"),                                       # 2 reviews
    (lambda: [_rv("triaged")] * 4 + [_rv(reason="false_positive")], "ok"),               # 80%
    (lambda: [_rv("triaged")] * 3 + [_rv(reason="expected")] * 4, "expected"),           # 4/7 expected
    (lambda: [_rv("triaged")] * 3 + [_rv(reason="false_positive")] * 3 + [_rv(reason="expected")], "false_positives"),
    (lambda: [_rv("triaged")] * 2 + [_rv()] * 4 + [_rv(reason="false_positive")] * 1 + [_rv(reason="expected")] * 1, "no_reason"),
    (lambda: [_rv("triaged")] * 3 + [_rv(reason="false_positive")] * 1 + [_rv(reason="expected")] * 1 + [_rv()] * 1, "mixed"),
])
def test_the_reading_of_a_check(make, verdict):
    c = _compute(make())["checks"][0]
    assert c["verdict"] == verdict, c
    assert (c["hint"] == "") == (verdict == "ok")


def test_the_trend_shows_every_week_of_the_window_with_gaps_as_zeros():
    now = _now()
    reviews = [_rv("triaged", reviewed_at=now), _rv(reason="expected", reviewed_at=now - timedelta(days=15))]
    trend = _compute(reviews, days=30)["trend"]
    weeks = [t["week"] for t in trend]
    assert weeks == sorted(set(weeks)) and len(weeks) >= 5
    assert sum(t["findings"] for t in trend) == 2
    assert trend[-1]["findings"] >= 1 and any(t["findings"] == 0 for t in trend)
    assert all(datetime.fromisoformat(w).weekday() == 0 for w in weeks)               # weeks start on Monday


def test_the_findings_worth_an_allowlist_entry_are_the_dismissed_ones_that_keep_firing():
    reviews = ([_rv(reason="expected", events=50, rid=1), _rv(reason="false_positive", events=120, rid=2),
                _rv(reason="duplicate", events=999, rid=3), _rv("triaged", events=500, rid=4),
                _rv(reason="expected", events=1, rid=5), _rv(via="bulk", events=700, rid=6)]
               + [_rv(reason="expected", events=2 + i, rid=100 + i) for i in range(12)])
    noisy = _compute(reviews)["recurring_noise"]
    assert [n["id"] for n in noisy[:2]] == [2, 1]                         # most events first
    ids = {n["id"] for n in noisy}
    assert not ids & {3, 4, 5, 6}                                         # not a duplicate, a triage, a one-off, or bulk
    assert len(noisy) == precision.NOISY_ROWS
    assert {"check", "title", "evidence", "channel", "sender", "events", "reason", "reviewed_at"} <= set(noisy[0])


def test_a_finding_that_stopped_firing_before_its_dismissal_is_not_noise():
    now = _now()
    stopped = _rv(reason="expected", events=40, rid=1, last_seen=now - timedelta(hours=2))
    at_review = _rv(reason="expected", events=40, rid=2, last_seen=now)
    again = _rv(reason="expected", events=40, rid=3, last_seen=now + timedelta(days=2))
    noisy = _compute([stopped, at_review, again])["recurring_noise"]
    assert [n["id"] for n in noisy] == [3] and noisy[0]["last_seen"] > noisy[0]["reviewed_at"]


def test_the_tools_are_ranked_by_how_much_was_reviewed():
    reviews = [_rv("triaged", channel="Bash")] * 4 + [_rv("triaged", channel="Read")] * 2 + [_rv("triaged", channel=None)]
    tools = _compute(reviews)["tools"]
    assert [t["tool"] for t in tools] == ["Bash", "Read", "(none)"] and tools[0]["judged"] == 4


def test_an_empty_readout_has_the_same_shape():
    out = _compute([])
    assert out["reviewed"]["judged"] == 0 and out["reviewed"]["actionable_rate"] is None
    assert out["reviewed"]["correct_low"] is None and out["checks"] == [] and out["recurring_noise"] == []
    assert out["bulk"] == {"findings": 0, "events": 0} and out["reviewed"]["verdict"] == "low_sample"
    assert len(out["trend"]) >= 5


# --- the endpoint ---

def test_only_an_admin_may_read_it(client, db_factory, raw_client):
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    c = TestClient(app)
    tok = c.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {tok}"})
    assert c.get("/api/precision").status_code == 403
    assert raw_client.get("/api/precision").status_code == 401
    assert client.get("/api/precision").status_code == 200


def test_the_window_is_when_it_was_reviewed_not_when_it_was_raised(client, db_factory):
    _add(db_factory, status="triaged", via="manual", ago_days=3, created_days_ago=200)       # old finding, fresh review
    _add(db_factory, status="triaged", via="manual", ago_days=45, created_days_ago=46)       # reviewed before the window
    assert _readout(client, days=30)["reviewed"]["findings"] == 1
    assert _readout(client, days=60)["reviewed"]["findings"] == 2
    assert _readout(client, days=0)["days"] == 1 and _readout(client, days=9999)["days"] == 365


def test_the_endpoint_counts_what_the_database_holds(client, db_factory):
    for status, reason in [("triaged", ""), ("triaged", ""), ("dismissed", "expected"),
                           ("dismissed", "false_positive"), ("dismissed", "")]:
        _add(db_factory, status=status, reason=reason, via="manual", ago_days=1, seen=3)
    _add(db_factory, status="dismissed", via="bulk", ago_days=1, seen=10)
    _add(db_factory, status="triaged", via="analyst", ago_days=1)
    _add(db_factory, status="triaged", owner_response={"action": "fixed"})           # answered, never reviewed
    _add(db_factory, status="dismissed")                                              # before the record existed
    _add(db_factory, status="open", severity="critical", created_days_ago=9)
    _add(db_factory, status="open", severity="low")
    out = _readout(client)
    r = out["reviewed"]
    assert (r["findings"], r["judged"], r["actionable"], r["expected"], r["false_positive"], r["unspecified"]) == (6, 6, 3, 1, 1, 1)
    assert r["events"] == 5 * 3 + 1 and r["via_analyst"] == 1
    assert out["bulk"] == {"findings": 1, "events": 10}
    assert out["not_counted"] == {"answered_by_owner": 1, "before_tracking": 1}
    assert out["backlog"]["open"] == 2 and out["backlog"]["open_high"] == 1 and out["backlog"]["oldest_open_days"] == 9
    assert out["truncated"] is False and out["limits"]["reasons"] == list(review.REASONS)


def test_a_reopened_finding_drops_out_of_the_readout(client, db_factory):
    fid = _add(db_factory)
    _patch(client, fid, "dismissed", reason="false_positive")
    assert _readout(client)["reviewed"]["false_positive"] == 1
    _patch(client, fid, "open")
    assert _readout(client)["reviewed"]["findings"] == 0


def test_one_orgs_reviews_are_not_anothers(client, db_factory):
    db = db_factory()
    users_cli.create_tenant(db, "globex", "Globex", plan="enterprise")
    other = db.query(Tenant).filter(Tenant.slug == "globex").first().id
    db.close()
    _add(db_factory, tenant_id=other, status="triaged", via="manual", ago_days=1)
    _add(db_factory, status="triaged", via="manual", ago_days=1)
    assert _readout(client)["reviewed"]["findings"] == 1


def test_a_result_that_hit_the_row_limit_says_so(client, db_factory, monkeypatch):
    monkeypatch.setattr(precision, "MAX_ROWS", 3)
    for _ in range(5):
        _add(db_factory, status="triaged", via="manual", ago_days=1)
    out = _readout(client)
    assert out["truncated"] is True and out["reviewed"]["findings"] == 3


def test_the_csv_is_the_per_check_table_with_the_overall_row_first(client, db_factory):
    for _ in range(4):
        _add(db_factory, status="triaged", via="manual", ago_days=1)
    _add(db_factory, status="dismissed", reason="false_positive", via="manual", ago_days=1)
    r = client.get("/api/precision", params={"format": "csv", "days": 14})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "palivane-precision.csv" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("scope,check,findings,events,needed_action,expected,false_positive") and "window_days=14" in lines[0]
    assert lines[1].startswith("overall,,5,5,4,0,1,0,0,5,80.0,80.0,80.0,ok")
    assert lines[2].startswith("check,dangerous_command,5,5,4,0,1,0,0,5,80.0")


# --- the labels the eval harness learns from ---

def _f(**kw):
    return Finding(id=1, status=kw.pop("status", "dismissed"), surface="agent_tools", sender="a@b.c",
                   subject="s", content="", **kw)


@pytest.mark.parametrize("kw,label", [
    ({"status": "triaged"}, "malicious"),
    ({"status": "dismissed", "review_reason": "false_positive", "review_via": "manual"}, "benign"),
    ({"status": "dismissed", "review_reason": "", "review_via": "manual"}, "benign"),
    ({"status": "dismissed"}, "benign"),                                                  # before records: as it always was
    ({"status": "dismissed", "review_reason": "expected", "review_via": "manual"}, None),
    ({"status": "dismissed", "review_reason": "accepted_risk", "review_via": "manual"}, None),
    ({"status": "dismissed", "review_reason": "duplicate", "review_via": "manual"}, None),
    ({"status": "dismissed", "review_via": "bulk"}, None),
    ({"status": "triaged", "review_via": "bulk"}, None),
    ({"status": "open"}, None),
])
def test_only_a_judgement_about_the_detector_becomes_a_label(kw, label):
    ex = finding_to_example(_f(**kw))
    assert (ex["label"] if ex else None) == label


def test_the_reason_travels_with_the_label():
    ex = finding_to_example(_f(review_reason="false_positive", review_via="manual"))
    assert ex["note"] == "analyst dismissed (false_positive)"
