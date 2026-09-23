"""What the dashboard tiles count, and that closing work actually clears them.

The tiles sit in one row in the same visual language, so they are read as answering the same
question. `open` was filtered to status=open and `high_risk` was not filtered at all, which
meant closing every finding drove one tile to zero and left the other at 89 — indistinguishable
from the console being broken, and reported as exactly that.
"""

from __future__ import annotations


def _mk(client, content, status=None, subject="t"):
    r = client.post("/api/analyze", json={"content": content, "subject": subject,
                                          "surface": "ai_usage", "persist": True})
    assert r.status_code == 200, r.text
    fid = r.json().get("finding_id")
    if fid and status:
        p = client.patch(f"/api/findings/{fid}", json={"status": status})
        assert p.status_code == 200, p.text
    return fid


def _stats(client):
    r = client.get("/api/stats")
    assert r.status_code == 200, r.text
    return r.json()


def test_closing_every_finding_clears_the_high_risk_tile(client):
    """The reported bug, as an assertion. Before the fix this ended at high_risk=1."""
    fid = _mk(client, "here is the key AKIA4YTGH2NBQF7XZP3K")
    assert _stats(client)["high_risk"] >= 1
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    s = _stats(client)
    assert s["high_risk"] == 0, "a dismissed finding is not outstanding high-risk work"
    assert s["open"] == 0


def test_total_still_counts_everything(client):
    """Scoping high_risk must not quietly turn `total` into a work queue too — it is the
    census, and the report depends on it staying one."""
    fid = _mk(client, "here is the key AKIA4YTGH2NBQF7XZP3K")
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    s = _stats(client)
    assert s["total"] == 1
    assert s["by_severity"], "severity census is independent of workflow state"


def test_benign_is_open_work_but_not_review_work(client):
    """Status is workflow, severity is judgement — deliberately independent. A benign finding
    nobody has looked at is legitimately open; it is not something needing review. Both
    numbers are reported so a queue of benign records cannot inflate the one people act on.
    """
    _mk(client, "what is the weather like today")
    s = _stats(client)
    assert s["open"] >= 1
    assert s["open_needs_review"] == 0, "benign is open, but not work"
    assert s["high_risk"] == 0


# --- Time window ------------------------------------------------------------------------
# The dashboard used to mix three clocks with nothing saying which was which: all-time
# aggregates, status=open backlog counts, and a Coverage panel fixed to 24h. The split
# below is the contract — flow follows the window, stock never does.

def _age(db_factory, fid, days):
    """Backdate a finding's last_seen. last_seen, not created_at: a repeat bumps the
    existing row rather than inserting a new one, so last_seen is what "recent activity"
    means. Goes through db_factory, not app.database.SessionLocal — the fixture rebinds
    get_db to a throwaway engine, and the module-level session points somewhere else."""
    from datetime import datetime, timedelta, timezone
    from app.models import Finding
    db = db_factory()
    try:
        f = db.query(Finding).filter(Finding.id == fid).one()
        f.last_seen = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
        db.commit()
    finally:
        db.close()


def _win(client, window):
    r = client.get(f"/api/stats?window={window}")
    assert r.status_code == 200, r.text
    return r.json()


def test_flow_follows_the_window_and_stock_does_not(client, db_factory):
    # Distinct subjects AND distinct signal categories: a repeat of the same actor,
    # surface and category set folds into the existing row (seen_count/last_seen) instead
    # of inserting, so two near-identical secrets would have been one finding and this
    # test would have been asserting against a single row it then backdated.
    recent = _mk(client, "here is the key AKIA4YTGH2NBQF7XZP3K", subject="recent")
    old = _mk(client, "ssn 123-45-6789 for the file", subject="older")
    assert recent != old, "the two fixtures must be separate findings for this to mean anything"
    _age(db_factory, old, days=10)

    day = _win(client, "24h")
    week = _win(client, "7d")
    month = _win(client, "30d")

    # FLOW: the aged finding drops out of the short windows.
    assert day["total"] == 1, "a 10-day-old finding is not activity in the last 24h"
    assert week["total"] == 1
    assert month["total"] == 2
    assert sum(day["by_surface"].values()) == 1
    assert sum(month["by_surface"].values()) == 2
    assert sum(day["by_severity"].values()) == 1

    # STOCK: both are still open work whatever window is showing. Windowing these would
    # hide a backlog, which is the one thing a queue count exists to surface.
    for s in (day, week, month):
        assert s["open"] == 2, "the queue does not shrink because the window is short"
        assert s["high_risk"] == 2


def test_previous_window_is_the_span_before_this_one(client, db_factory):
    old = _mk(client, "here is the key AKIA4YTGH2NBQF7XZP3K", subject="older")
    _age(db_factory, old, days=3)
    # 24h window: the 3-day-old finding is in neither this window nor the 24h before it.
    assert _win(client, "24h")["previous"]["total"] == 0
    # 7d window: its previous span is 14d..7d ago, still not where the finding sits.
    assert _win(client, "7d")["previous"]["total"] == 0
    # 30d: the finding is inside the current window, so the prior span is empty and the
    # current one holds it.
    month = _win(client, "30d")
    assert month["total"] == 1 and month["previous"]["total"] == 0


def test_all_time_has_no_previous_to_compare_against(client):
    _mk(client, "here is the key AKIA4YTGH2NBQF7XZP3K")
    s = _win(client, "all")
    assert s["window"] == "all"
    assert s["previous"] is None, "a delta against all of history is not a number"


def test_default_window_is_24h(client):
    assert _stats(client)["window"] == "24h"


def test_an_unknown_window_is_rejected_rather_than_silently_all_time(client):
    r = client.get("/api/stats?window=forever")
    assert r.status_code == 400
    assert "24h" in r.json()["detail"]
