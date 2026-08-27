"""Cloud-storage plane: /api/scan/s3 — S3 object secret/PII scan + public-exposure escalation."""

from __future__ import annotations

import app.main as main
from app import users as users_cli


def _seed(db_factory, slug="acme"):
    db = db_factory()
    users_cli.create_tenant(db, slug, slug.title())
    db.close()


def _scan(raw_client, objects, public=False, token="ext-secret", record=False):
    return raw_client.post(
        "/api/scan/s3",
        json={"bucket": "data-bkt", "region": "us-east-1", "public": public,
              "objects": objects, "record": record},
        headers={"X-Palivane-Token": token},
    )


def _setup(db_factory, monkeypatch):
    _seed(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")


def test_requires_valid_token(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    assert raw_client.post("/api/scan/s3", json={"bucket": "b", "objects": []}).status_code == 401
    assert _scan(raw_client, [{"key": "a", "content": "x"}], token="nope").status_code == 401


def test_clean_object_allowed(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"key": "readme.txt", "content": "just some docs, nothing secret"}]).json()
    assert body["action"] == "allow" and body["objects"] == [] and body["scanned"] == 1


def test_secret_object_flagged(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"key": "dump/prod.env", "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"}]).json()
    assert body["action"] in ("block", "warn")
    assert body["objects"][0]["key"] == "dump/prod.env"
    assert any(s["category"] == "secret_leak" for s in body["objects"][0]["signals"])


def test_public_bucket_escalates_to_block(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    obj = [{"key": "dump/prod.env", "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"}]
    private = _scan(raw_client, obj, public=False).json()
    public = _scan(raw_client, obj, public=True).json()
    # Same content: a private hit may be block-or-warn, but a PUBLIC bucket is always block,
    # tagged public for alerting.
    assert public["action"] == "block"
    assert public["public"] is True and public["objects"][0]["action"] == "block"
    assert public["objects"][0]["public"] is True
    assert private["public"] is False


def test_record_flag_scans_and_flags(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    # record=True persists server-side; the response still carries the flagged object.
    body = _scan(raw_client, [{"key": "leak.env", "content": "token=AKIAIOSFODNN7EXAMPLE\n"}],
                 public=True, record=True).json()
    assert body["objects"] and body["objects"][0]["public"] is True
    assert body["action"] == "block"


# --- client-side detection (metadata only) ------------------------------------------------
# palivane-s3-scan now detects in the account that owns the bucket and sends findings, not
# object text. These cover the shape the server has to accept and score.

def _finding(category="secret_leak", label="AWS access key id", line=1, masked="AKIA••••MPLE"):
    return {"category": category, "label": label, "line": line, "masked": masked}


def test_client_findings_are_scored_without_any_content(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    r = _scan(raw_client, [{"key": "exports/.env", "findings": [_finding()]}]).json()
    assert r["action"] == "block"
    obj = r["objects"][0]
    assert obj["key"] == "exports/.env" and obj["action"] == "block"
    assert obj["risk_score"] >= 70


def test_no_object_text_is_required_or_echoed(raw_client, db_factory, monkeypatch):
    """The point of the change: the request carries no bytes from the bucket, and the
    response cannot leak any either."""
    _setup(db_factory, monkeypatch)
    r = _scan(raw_client, [{"key": "db.sql", "findings": [_finding(masked="AKIA••••7777")]}])
    body = r.text
    assert "AKIAIOSFODNN7EXAMPLE" not in body       # nothing that looks like a real value
    assert "content" not in r.json()["objects"][0]


def test_pii_and_phi_categories_are_accepted(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    for cat in ("pii_exposure", "phi_exposure"):
        r = _scan(raw_client, [{"key": f"{cat}.csv",
                                "findings": [_finding(category=cat, label="US Social Security number",
                                                      masked="412-••••7390")]}]).json()
        assert r["objects"], f"{cat} produced no finding"
        assert r["objects"][0]["action"] in ("warn", "block")


def test_public_bucket_still_escalates_with_client_findings(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    obj = [{"key": "leak.env", "findings": [_finding()]}]
    private = _scan(raw_client, obj, public=False).json()
    public = _scan(raw_client, obj, public=True).json()
    assert public["action"] == "block" and public["objects"][0]["public"] is True
    assert private["public"] is False


def test_legacy_content_payload_still_works(raw_client, db_factory, monkeypatch):
    """Older installed CLIs still POST object text; they must not break on upgrade."""
    _setup(db_factory, monkeypatch)
    r = _scan(raw_client, [{"key": "old.env",
                            "content": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]).json()
    assert r["objects"] and r["objects"][0]["action"] == "block"


def test_an_object_with_no_findings_is_not_reported(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    r = _scan(raw_client, [{"key": "readme.txt", "findings": []}]).json()
    assert r["action"] == "allow" and r["objects"] == []


def test_recorded_verdict_matches_the_response(raw_client, db_factory, monkeypatch):
    """A client-detected object was answered 'high' and stored 'benign', so `--record`
    filed every finding below the warn line: nothing in the console, no alert, no SIEM
    forward. The scorer now sees the client's evidence, so one verdict serves both."""
    from app.models import Finding
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"key": "prod.env", "findings": [_finding()]}], record=True).json()
    db = db_factory()
    rows = db.query(Finding).all()
    db.close()
    assert len(rows) == 1
    assert rows[0].severity == body["objects"][0]["severity"]
    assert rows[0].risk_score == body["objects"][0]["risk_score"]


def test_disabled_check_suppresses_a_client_finding(raw_client, db_factory, monkeypatch):
    """Client-reported evidence is policy-filtered like the server's own. An admin who
    turned a category off must not get it back because detection moved to the client."""
    from app.models import Tenant
    _setup(db_factory, monkeypatch)
    db = db_factory()
    db.query(Tenant).filter(Tenant.slug == "acme").one().disabled_checks = "secret_leak"
    db.commit(); db.close()
    body = _scan(raw_client, [{"key": "prod.env", "findings": [_finding()]}]).json()
    assert body["action"] == "allow" and body["objects"] == []
