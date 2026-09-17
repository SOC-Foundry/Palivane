"""What the dashboard tiles count, and that closing work actually clears them.

The tiles sit in one row in the same visual language, so they are read as answering the same
question. `open` was filtered to status=open and `high_risk` was not filtered at all, which
meant closing every finding drove one tile to zero and left the other at 89 — indistinguishable
from the console being broken, and reported as exactly that.
"""

from __future__ import annotations


def _mk(client, content, status=None):
    r = client.post("/api/analyze", json={"content": content, "subject": "t",
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
