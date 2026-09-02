"""Self-remediation: the person a finding belongs to answers for it.

The security value of this feature is entirely in what it does NOT allow, so most of these
test the boundaries rather than the happy path.
"""

from __future__ import annotations

from app.models import Finding, Tenant

ADMIN = "admin@acme.com"          # the `client` fixture's authenticated user


def _tid(db_factory):
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == "acme").first().id
    finally:
        db.close()


def _finding(db_factory, sender, **kw):
    db = db_factory()
    f = Finding(tenant_id=_tid(db_factory), sender=sender,
                subject=kw.pop("subject", "a doc"), severity=kw.pop("severity", "high"),
                risk_score=80, surface="collab", status=kw.pop("status", "open"), **kw)
    db.add(f); db.commit(); db.refresh(f)
    fid = f.id
    db.close()
    return fid


def test_only_your_own_findings_come_back(client, db_factory):
    mine = _finding(db_factory, ADMIN)
    theirs = _finding(db_factory, "someone.else@acme.com")
    ids = [f["id"] for f in client.get("/api/my/findings").json()["findings"]]
    assert mine in ids and theirs not in ids


def test_attribution_is_case_insensitive(client, db_factory):
    fid = _finding(db_factory, ADMIN.upper())
    assert fid in [f["id"] for f in client.get("/api/my/findings").json()["findings"]]


def test_responding_records_an_attributed_answer(client, db_factory):
    fid = _finding(db_factory, ADMIN)
    r = client.post(f"/api/my/findings/{fid}/respond",
                    json={"action": "fixed", "note": "removed the share link"})
    assert r.status_code == 200
    resp = r.json()["owner_response"]
    assert resp["action"] == "fixed" and resp["by"] == ADMIN and resp["at"]


def test_responding_never_dismisses(client, db_factory):
    """The one person with a motive to bury a real leak must not be able to close it."""
    fid = _finding(db_factory, ADMIN)
    r = client.post(f"/api/my/findings/{fid}/respond", json={"action": "approved", "note": "ok"})
    assert r.json()["status"] == "triaged"
    for attempt in ("dismissed", "closed", "resolved"):
        bad = client.post(f"/api/my/findings/{fid}/respond",
                          json={"action": attempt, "note": "x"})
        assert bad.status_code == 422


def test_cannot_answer_for_someone_else(client, db_factory):
    """404 rather than 403: whether a finding exists for another person is not something an
    arbitrary user should be able to probe."""
    theirs = _finding(db_factory, "someone.else@acme.com")
    r = client.post(f"/api/my/findings/{theirs}/respond", json={"action": "fixed"})
    assert r.status_code == 404


def test_not_mine_requires_a_note(client, db_factory):
    """"Not mine" with no explanation gives an admin nothing to act on."""
    fid = _finding(db_factory, ADMIN)
    assert client.post(f"/api/my/findings/{fid}/respond",
                       json={"action": "not_mine"}).status_code == 422
    assert client.post(f"/api/my/findings/{fid}/respond",
                       json={"action": "not_mine", "note": "belongs to finance"}).status_code == 200


def test_the_answer_is_visible_to_the_admin_queue(client, db_factory):
    """An admin should see 'already answered' while triaging, not have to open each row."""
    fid = _finding(db_factory, ADMIN)
    client.post(f"/api/my/findings/{fid}/respond", json={"action": "fixed", "note": "done"})
    row = next(f for f in client.get("/api/findings?status=triaged").json()["findings"]
               if f["id"] == fid)
    assert row["owner_response"]["action"] == "fixed"


def test_owners_do_not_get_stored_prose(client, db_factory):
    """Telling someone their document leaked must not become a content-reading surface."""
    fid = _finding(db_factory, ADMIN, content="a secret AKIA000")
    row = next(f for f in client.get("/api/my/findings").json()["findings"] if f["id"] == fid)
    assert "content" not in row
    assert row["remediation"] is not None
