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
        headers={"X-Warden-Token": token},
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
