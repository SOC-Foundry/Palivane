"""What a dismissal is allowed to silence.

Recurrence folding is right: the same actor pasting the same secret twice is one finding,
not two, and the second occurrence must not re-alert. But folding also carried the prior
row's STATUS, so a dismissed finding absorbed every future occurrence silently — seen_count
climbed, status stayed dismissed, and the console (default filter: status=open) showed
nothing at all.

That turned a queue-clearing gesture into a permanent mute on every event class the tenant
had ever recorded. It was reported the only way it can be: "I sent an SSN and I don't see
my alert." Silence read as the product being broken, which is the correct reading.
"""

from __future__ import annotations

SSN = {"content": "my ssn is 000-00-0000", "subject": "Prompt to claude-code",
       "surface": "ai_usage", "persist": True}


def _analyze(client, **over):
    body = dict(SSN); body.update(over)
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _row(client, fid):
    rows = client.get("/api/findings", params={"limit": 500}).json()
    rows = rows.get("findings", rows) if isinstance(rows, dict) else rows
    return next(f for f in rows if f["id"] == fid)


def test_a_live_leak_reopens_a_dismissed_finding(client):
    """The reported bug. Before the fix this ended with the row still dismissed and the
    open view empty, while the leak had just happened again."""
    fid = _analyze(client)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})

    again = _analyze(client)
    assert again["finding_id"] == fid, "still one finding — folding is not the bug"
    assert again["recurrence"] == 2

    row = _row(client, fid)
    assert row["status"] == "open", "a fresh high-severity leak was swallowed by a dismissal"
    assert row["seen_count"] == 2, "reopening must not lose the recurrence count"


def test_it_shows_up_where_someone_is_actually_looking(client):
    """Reopening the row is only worth anything if it lands in the default view."""
    fid = _analyze(client)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    _analyze(client)
    rows = client.get("/api/findings", params={"status": "open", "limit": 500}).json()
    rows = rows.get("findings", rows) if isinstance(rows, dict) else rows
    assert [f["id"] for f in rows] == [fid]


def test_a_rescanned_artifact_stays_dismissed(client, raw_client):
    """The other half, and the reason the rule is not severity alone. An at-rest scan
    re-reads the same hardcoded key on every pass — a repo full of test fixtures fires
    the same critical finding forever. That is one fact re-observed, not a new act, so
    dismissing it has to hold or the queue refills on its own and dismissal is useless.
    """
    key = client.post("/api/apikeys",
                      json={"label": "scan", "actor": "dev@acme.com"}).json()["token"]
    body = {"host": "laptop-1", "record": True,
            "items": [{"path": "/home/dev/.aws/credentials", "masked": "AKIA****************",
                       "secret_types": ["aws_access_key"], "world_readable": True,
                       "verified": True, "source": "palivane-secrets"}]}
    r = raw_client.post("/api/scan/secrets", json=body, headers={"X-Palivane-Token": key})
    assert r.status_code == 200, r.text
    assert r.json()["flagged"] == 1, r.text

    rows = client.get("/api/findings", params={"limit": 500}).json()["findings"]
    fid = next(f["id"] for f in rows if f["surface"] == "secrets")
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})

    raw_client.post("/api/scan/secrets", json=body, headers={"X-Palivane-Token": key})
    row = _row(client, fid)
    assert row["seen_count"] == 2, "the re-scan should still have folded"
    assert row["status"] == "dismissed", \
        "a re-scan of the same artifact must not resurrect a dismissal"


def test_dismissing_low_noise_still_means_dismissed(client):
    """The other half. Dismissal exists to suppress the recurring thing an analyst has
    judged to be nothing — if every repeat reopened it, dismissal would do nothing at all
    and the queue would refill on its own."""
    r = _analyze(client, content="what is the weather like today", persist_benign=True)
    fid = r.get("finding_id")
    if fid is None:                      # benign captures may not persist in this config
        return
    assert r["severity"] in ("benign", "low"), r["severity"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    _analyze(client, content="what is the weather like today", persist_benign=True)
    assert _row(client, fid)["status"] == "dismissed"


def test_triage_in_progress_is_left_alone(client):
    """Triaged means someone is working it. A recurrence is expected while that is true,
    and yanking the row back to open would undo their bookkeeping."""
    fid = _analyze(client)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "triaged"})
    _analyze(client)
    assert _row(client, fid)["status"] == "triaged"
