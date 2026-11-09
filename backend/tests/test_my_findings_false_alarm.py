"""Your findings: the 'Not a leak' answer, and a filter that follows the person's answers."""
from __future__ import annotations

from app.models import Finding

SSN = "51" + "3-2" + "7-48" + "61"


def _mine(client, db_factory, n=1):
    email = client.get("/api/auth/me").json()["user"]["email"]
    ids = []
    for i in range(n):
        fid = client.post("/api/analyze", json={"content": f"case {i}: ssn {SSN}", "surface": "ai_usage",
                                                "persist": True}).json()["finding_id"]
        db = db_factory()
        try:
            row = db.get(Finding, fid)
            row.sender = email
            db.commit()
        finally:
            db.close()
        ids.append(fid)
    return ids


def _ids(client, status):
    return {f["id"] for f in client.get("/api/my/findings", params={"status": status}).json()["findings"]}


def _status(db_factory, fid):
    db = db_factory()
    try:
        return db.get(Finding, fid).status
    finally:
        db.close()


def test_a_false_alarm_stays_open_for_the_security_team(client, db_factory):
    fid, = _mine(client, db_factory)
    r = client.post(f"/api/my/findings/{fid}/respond", json={"action": "false_alarm", "note": "test value"})
    assert r.status_code == 200 and r.json()["status"] == "open"
    assert _status(db_factory, fid) == "open"
    # answered, so it leaves the person's "needs an answer" view, though still open in the queue
    assert fid not in _ids(client, "open") and fid in _ids(client, "triaged")
    row = next(f for f in client.get("/api/findings", params={"limit": 50}).json()["findings"] if f["id"] == fid)
    assert row["owner_response"]["action"] == "false_alarm"
    assert client.get("/api/precision").json()["backlog"]["owner_false_alarm"] == 1


def test_other_answers_still_move_it_to_triaged(client, db_factory):
    fid, = _mine(client, db_factory)
    assert client.post(f"/api/my/findings/{fid}/respond", json={"action": "fixed"}).json()["status"] == "triaged"


def test_revising_to_false_alarm_puts_it_back_in_front_of_the_team(client, db_factory):
    fid, = _mine(client, db_factory)
    client.post(f"/api/my/findings/{fid}/respond", json={"action": "fixed"})
    r = client.post(f"/api/my/findings/{fid}/respond", json={"action": "false_alarm"})
    assert r.json()["status"] == "open"


def test_an_admin_triage_is_not_undone_by_a_false_alarm(client, db_factory):
    fid, = _mine(client, db_factory)
    client.patch(f"/api/findings/{fid}", json={"status": "triaged"})
    r = client.post(f"/api/my/findings/{fid}/respond", json={"action": "false_alarm"})
    assert r.json()["status"] == "triaged"
