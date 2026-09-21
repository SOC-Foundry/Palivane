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


# --- the reopen has to reach somebody ---------------------------------------------------
#
# Reopening the row fixes the console. It fixed nothing for the people who do not sit in the
# console: sinks fire only in the new-row branch, so a reopen — the one case where an
# analyst's own judgement has just been contradicted by events — went out to nobody.

def _webhooked(client, db_factory, monkeypatch):
    """Point the tenant's alert webhook at a list instead of the network."""
    from app import alerts
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)
    # Real-time alerting is gated on severity AND digest mode; "off" is the real-time mode.
    db = db_factory()
    from app.models import Tenant
    t = db.query(Tenant).first()
    t.alert_webhook = "https://hooks.example.com/x"
    t.alert_min_severity = "high"
    t.alert_digest = "off"
    db.commit(); db.close()
    return sent


def test_a_reopen_fires_the_alert_sinks(client, db_factory, monkeypatch):
    sent = _webhooked(client, db_factory, monkeypatch)
    fid = _analyze(client)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    sent.clear()                      # ignore the first-sighting alert

    r = _analyze(client)
    assert r["reopened"] is True
    assert len(sent) == 1, "the reopen reached nobody outside the console"


def test_the_alert_says_it_is_a_reopen(client, db_factory, monkeypatch):
    """It arrives looking like any other alert, and the responder has already closed this
    one. Unmarked, the likely reaction is to close it again."""
    sent = _webhooked(client, db_factory, monkeypatch)
    fid = _analyze(client)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    sent.clear()
    _analyze(client)

    text = sent[0]["text"]
    assert "REOPENED" in text, text
    assert sent[0]["palivane"]["reopened"] is True
    assert sent[0]["palivane"]["recurrence"] == 2


def test_it_fires_on_the_edge_only_not_on_every_repeat(client, db_factory, monkeypatch):
    """This is the rate limit, and the reason there is no cooldown column: the transition
    fires, and the row is open afterwards, so further repeats fold into an open row and
    send nothing. Ringing the webhook once per recurrence would be its own outage."""
    sent = _webhooked(client, db_factory, monkeypatch)
    fid = _analyze(client)["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    sent.clear()

    _analyze(client)                  # dismissed -> open: one alert
    for _ in range(5):
        _analyze(client)              # already open: silent
    assert len(sent) == 1, f"fired {len(sent)} times for one reopen"


def test_a_recurrence_that_stays_dismissed_alerts_nobody(client, raw_client, db_factory,
                                                         monkeypatch):
    """The at-rest half. No reopen, so no alert — otherwise dismissing a re-scanned fixture
    secret would page somebody on every scan pass."""
    sent = _webhooked(client, db_factory, monkeypatch)
    key = client.post("/api/apikeys",
                      json={"label": "scan2", "actor": "dev@acme.com"}).json()["token"]
    body = {"host": "laptop-1", "record": True,
            "items": [{"path": "/home/dev/.aws/credentials", "masked": "AKIA****************",
                       "secret_types": ["aws_access_key"], "world_readable": True,
                       "verified": True, "source": "palivane-secrets"}]}
    raw_client.post("/api/scan/secrets", json=body, headers={"X-Palivane-Token": key})
    rows = client.get("/api/findings", params={"limit": 500}).json()["findings"]
    fid = next(f["id"] for f in rows if f["surface"] == "secrets")
    client.patch(f"/api/findings/{fid}", json={"status": "dismissed"})
    sent.clear()

    raw_client.post("/api/scan/secrets", json=body, headers={"X-Palivane-Token": key})
    assert sent == []
