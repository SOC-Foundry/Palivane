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


# --- Document owners: findings about a document you own are yours too ------------------
#
# content_origin attaches {source, ref, title, owner, ...} when leaked content overlaps a
# document scanned at rest. The owner of that document sees the finding and may answer it
# the same way the sender can. Ownership grants nothing else.

from fastapi.testclient import TestClient  # noqa: E402

from app import users as users_cli  # noqa: E402
from app.main import app  # noqa: E402

OWNER = "owner@acme.com"
COLLEAGUE = "colleague@acme.com"


def _origin(owner):
    return {"source": "gdrive", "ref": "file-1", "title": "Q3 plan.docx", "owner": owner,
            "containment": 0.9, "sensitive": True}


def _login(db_factory, email, tenant="acme", role="analyst"):
    """A signed-in (non-admin by default) user of `tenant`, logging in with the org slug so
    an address that exists in two tenants is unambiguous."""
    db = db_factory()
    users_cli.create_user(db, tenant, email, "password123", role)
    db.close()
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": "password123", "org": tenant})
    assert r.status_code == 200, r.text
    c.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})
    return c


def _ids(c, status="open"):
    r = c.get(f"/api/my/findings?status={status}")
    assert r.status_code == 200, r.text
    return [f["id"] for f in r.json()["findings"]]


def test_owner_sees_a_finding_about_their_document(client, db_factory):
    fid = _finding(db_factory, COLLEAGUE, origin=_origin("Owner@Acme.COM"))
    assert fid in _ids(_login(db_factory, OWNER))
    # The sender still sees it too: owner matching adds rows, it never takes any away.
    assert fid in _ids(_login(db_factory, COLLEAGUE))


def test_non_owner_does_not_see_it(client, db_factory):
    fid = _finding(db_factory, COLLEAGUE, origin=_origin(OWNER))
    assert fid not in _ids(client, "all")                           # admin, neither party
    assert fid not in _ids(_login(db_factory, "bystander@acme.com"), "all")


def test_owner_match_is_exact_not_substring(client, db_factory):
    """`owner@acme.com` must not match a document owned by a longer address that merely
    contains it, and rows without an origin owner never match."""
    rows = {_finding(db_factory, COLLEAGUE, origin=_origin("x" + OWNER)),
            _finding(db_factory, COLLEAGUE, origin=_origin(OWNER + ".evil")),
            _finding(db_factory, COLLEAGUE, origin={"source": "gdrive", "title": "no owner"}),
            _finding(db_factory, COLLEAGUE)}                         # no origin at all
    assert not rows & set(_ids(_login(db_factory, OWNER), "all"))


def test_owner_email_in_two_tenants_only_sees_their_own_tenant(client, db_factory):
    """The same owner address exists in acme and beta, and each tenant has a finding about a
    document owned by that address. Each login sees only its own tenant's row, in the list
    and at the respond endpoint (404 for the other tenant's)."""
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta Corp")
    beta_id = db.query(Tenant).filter(Tenant.slug == "beta").first().id
    f = Finding(tenant_id=beta_id, sender="someone@beta.com", subject="beta doc",
                severity="high", risk_score=80, surface="collab", status="open",
                origin=_origin(OWNER))
    db.add(f); db.commit(); beta_fid = f.id
    db.close()
    acme_fid = _finding(db_factory, COLLEAGUE, origin=_origin(OWNER))

    acme_owner = _login(db_factory, OWNER, tenant="acme")
    beta_owner = _login(db_factory, OWNER, tenant="beta")
    assert _ids(acme_owner, "all") == [acme_fid]
    assert _ids(beta_owner, "all") == [beta_fid]
    assert acme_owner.post(f"/api/my/findings/{beta_fid}/respond",
                           json={"action": "fixed"}).status_code == 404
    assert beta_owner.post(f"/api/my/findings/{acme_fid}/respond",
                           json={"action": "fixed"}).status_code == 404


def test_owner_may_answer_like_a_sender(client, db_factory):
    fid = _finding(db_factory, COLLEAGUE, origin=_origin(OWNER))
    owner = _login(db_factory, OWNER)
    r = owner.post(f"/api/my/findings/{fid}/respond",
                   json={"action": "fixed", "note": "restricted the share"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "triaged"                          # answered, not closed
    resp = r.json()["owner_response"]
    assert resp["by"] == OWNER and resp["as"] == "owner" and resp["action"] == "fixed"
    # The same boundaries a sender has: no verdicts, and not_mine needs a note.
    assert owner.post(f"/api/my/findings/{fid}/respond",
                      json={"action": "dismissed"}).status_code == 422
    assert owner.post(f"/api/my/findings/{fid}/respond",
                      json={"action": "not_mine"}).status_code == 422
    # Revising your own answer is fine.
    assert owner.post(f"/api/my/findings/{fid}/respond",
                      json={"action": "approved", "note": "shared with the auditor"}
                      ).status_code == 200


def test_non_owner_cannot_answer(client, db_factory):
    fid = _finding(db_factory, COLLEAGUE, origin=_origin(OWNER))
    bystander = _login(db_factory, "bystander@acme.com")
    assert bystander.post(f"/api/my/findings/{fid}/respond",
                          json={"action": "fixed"}).status_code == 404


def test_sender_answer_is_tagged_as_sender(client, db_factory):
    fid = _finding(db_factory, ADMIN, origin=_origin(OWNER))
    r = client.post(f"/api/my/findings/{fid}/respond", json={"action": "fixed"})
    assert r.status_code == 200 and r.json()["owner_response"]["as"] == "sender"


def test_one_party_cannot_overwrite_the_others_answer(client, db_factory):
    """A finding can belong to two people. Neither may silently replace the other's answer."""
    fid = _finding(db_factory, COLLEAGUE, origin=_origin(OWNER))
    sender = _login(db_factory, COLLEAGUE)
    owner = _login(db_factory, OWNER)
    assert sender.post(f"/api/my/findings/{fid}/respond",
                       json={"action": "approved", "note": "my manager signed off"}
                       ).status_code == 200
    assert owner.post(f"/api/my/findings/{fid}/respond",
                      json={"action": "fixed"}).status_code == 409
    row = next(f for f in client.get("/api/findings?status=triaged").json()["findings"]
               if f["id"] == fid)
    assert row["owner_response"]["by"] == COLLEAGUE


def test_owner_gains_no_triage_powers(client, db_factory):
    """Ownership is a reason to see and answer, never a triage right. A non-admin owner
    cannot dismiss (single or bulk), allowlist, purge or bulk-dismiss their document's
    finding, and answering it leaves it open to the admin."""
    fid = _finding(db_factory, COLLEAGUE, origin=_origin(OWNER))
    owner = _login(db_factory, OWNER)
    assert owner.patch(f"/api/findings/{fid}", json={"status": "dismissed"}).status_code == 403
    assert owner.post("/api/findings/bulk-status",
                      json={"ids": [fid], "status": "dismissed"}).status_code == 403
    assert owner.post("/api/allowlist",
                      json={"kind": "path", "pattern": "/q3-plan", "reason": "my document",
                            "finding_id": fid}).status_code == 403
    assert owner.post("/api/findings/purge").status_code == 403
    assert owner.post("/api/findings/dismiss-benign").status_code == 403
    owner.post(f"/api/my/findings/{fid}/respond", json={"action": "approved", "note": "ok"})
    db = db_factory()
    try:
        assert db.get(Finding, fid).status == "triaged"
    finally:
        db.close()
