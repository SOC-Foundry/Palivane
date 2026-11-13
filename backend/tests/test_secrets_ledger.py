"""Where a credential travelled, and proof that its rotation took. The value is never
stored: the ledger keys on a per-org keyed fingerprint of it."""
from __future__ import annotations

from datetime import timedelta

from app import secrets_ledger
from app.detectors.base import AnalysisInput, Surface
from app.detectors.patterns import find_secret_matches
from app.models import SecretRotation, SecretSighting, Tenant
from app.service import run_analysis

AWS = "AKIAIOSFODNN7QXAMPLE"
GH = "ghp_wY3kD8fJ2mNp6qRt7vBx1zLc4hAe5gUi9oKs"


def _tid(db_factory, slug="acme"):
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == slug).one().id
    finally:
        db.close()


def _event(db, tid, text, actor="dev@acme.com", channel="claude-code", surface=Surface.AI_USAGE):
    return run_analysis(AnalysisInput(content=text, sender=actor, channel=channel, surface=surface,
                                      subject="prompt"), persist=True, db=db, tenant_id=tid)


def test_the_matcher_returns_values_once_each_and_skips_placeholders():
    text = f"use {AWS} and {GH}, then {AWS} again; the docs say sk_test_xxxxxxxxxxxxxxxxxxxxxxxx"
    matches = find_secret_matches(text)
    assert [v for _, v in matches] == [AWS, GH]
    assert matches[0][0] == "AWS access key id"
    assert find_secret_matches("API_KEY=your-key-here") == []


def test_a_fingerprint_is_stable_per_org_and_one_way():
    a, b = secrets_ledger.fingerprint(1, AWS), secrets_ledger.fingerprint(1, " " + AWS + "\n")
    assert a == b and len(a) == 32 and AWS not in a
    assert secrets_ledger.fingerprint(2, AWS) != a


def test_sightings_follow_a_secret_across_people_tools_and_findings(client, db_factory):
    tid = _tid(db_factory)
    db = db_factory()
    r1 = _event(db, tid, f"deploy with {AWS}", actor="dev@acme.com", channel="claude-code")
    r2 = _event(db, tid, f"why does {AWS} fail", actor="ops@acme.com", channel="chatgpt")
    r3 = _event(db, tid, f"{AWS}", actor="dev@acme.com", channel="Bash", surface=Surface.AGENT_TOOLS)
    r4 = _event(db, tid, f"token {GH}", actor="dev@acme.com")
    assert db.query(SecretSighting).count() == 4
    out = client.get(f"/api/findings/{r1['finding_id']}/secrets").json()["secrets"]
    assert len(out) == 1
    t = out[0]
    assert t["label"] == "AWS access key id" and t["sightings"] == 3
    assert t["actors"] == ["dev@acme.com", "ops@acme.com"]
    assert sorted(t["tools"]) == ["agent_tools/Bash", "ai_usage/chatgpt", "ai_usage/claude-code"]
    assert sorted(t["findings"]) == sorted({r1["finding_id"], r2["finding_id"], r3["finding_id"]})
    assert t["rotation"] == {"status": "none"}
    assert r4["finding_id"] not in t["findings"]
    db.close()


def test_a_recurrence_adds_no_second_sighting(client, db_factory):
    tid = _tid(db_factory)
    db = db_factory()
    a = _event(db, tid, f"deploy with {AWS}")
    b = _event(db, tid, f"deploy with {AWS}")
    assert a["finding_id"] == b["finding_id"]
    assert db.query(SecretSighting).count() == 1
    db.close()


def test_rotation_is_watched_then_verified_or_contradicted(client, db_factory):
    tid = _tid(db_factory)
    db = db_factory()
    r = _event(db, tid, f"deploy with {AWS}")
    fp = secrets_ledger.fingerprint(tid, AWS)
    out = client.post(f"/api/secrets/{fp}/rotated", json={"note": "rotated in IAM"})
    assert out.status_code == 200, out.text
    assert out.json()["rotation"]["status"] == "watching"
    assert out.json()["rotation"]["rotated_by"] == "admin@acme.com" and out.json()["rotation"]["verify_due"]
    # A week passes with no sighting: verified, and the record says when.
    rot = db.query(SecretRotation).one()
    rot.rotated_at -= timedelta(days=8)
    for sg in db.query(SecretSighting).all():
        sg.seen_at -= timedelta(days=9)          # the sighting that led to the rotation predates it
    db.commit()
    t = client.get(f"/api/findings/{r['finding_id']}/secrets").json()["secrets"][0]
    assert t["rotation"]["status"] == "verified" and t["rotation"]["verified_at"]
    rots = client.get("/api/secrets/rotations").json()["rotations"]
    assert [(x["secret"], x["status"]) for x in rots] == [(fp, "verified")]
    # The old value shows up again (a new finding): the rotation did not take.
    _event(db, tid, f"still using {AWS} here", actor="ops@acme.com")
    t = client.get(f"/api/findings/{r['finding_id']}/secrets").json()["secrets"][0]
    assert t["rotation"]["status"] == "still_seen" and t["rotation"]["last_seen_after"]
    # Rotating again starts the watch over.
    out = client.post(f"/api/secrets/{fp}/rotated", json={})
    assert out.json()["rotation"]["status"] == "watching"
    audit = client.get("/api/audit").json()
    entries = audit if isinstance(audit, list) else audit.get("entries") or audit.get("items") or []
    assert sum(1 for e in entries if e.get("action") == "secret.rotated") == 2
    db.close()


def test_an_unknown_secret_and_another_orgs_secret_are_not_found(client, db_factory):
    from app import users as users_cli
    tid = _tid(db_factory)
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta")
    other = _tid(db_factory, "beta")
    _event(db, other, f"deploy with {AWS}")
    db.close()
    assert client.post(f"/api/secrets/{secrets_ledger.fingerprint(other, AWS)}/rotated", json={}).status_code == 404
    assert client.post(f"/api/secrets/{secrets_ledger.fingerprint(tid, AWS)}/rotated", json={}).status_code == 404


def test_a_finding_without_a_secret_has_no_ledger(client, db_factory):
    tid = _tid(db_factory)
    db = db_factory()
    r = _event(db, tid, "customer SSN 123-45-6789")
    assert r["finding_id"]
    assert client.get(f"/api/findings/{r['finding_id']}/secrets").json() == {"secrets": []}
    db.close()
