"""Metadata-only-by-default storage, per-tenant envelope encryption (BYOK), entropy
redaction, and content TTL scrub — the honeypot-reduction changes."""

from __future__ import annotations

import app.service as service
from app.models import Finding, Tenant


def _ingest_leak(client, raw_client, content="my AWS key AKIA4YTGH2NBQF7XZP3K here"):
    client.patch("/api/tenant", json={})  # ensure tenant row exists
    key = client.post("/api/apikeys", json={"label": "k", "actor": "a@acme.com"}).json()["token"]
    raw_client.post("/api/ingest/ai-usage", json={"content": content, "destination": "https://chatgpt.com/"},
                    headers={"X-Warden-Token": key})


def test_metadata_only_by_default_stores_no_prose(client, raw_client, db_factory, monkeypatch):
    monkeypatch.setattr(service.settings, "store_content", False)   # global default
    _ingest_leak(client, raw_client,
                 "secret plan: acquire Acme, key AKIA4YTGH2NBQF7XZP3K")
    db = db_factory()
    f = db.query(Finding).order_by(Finding.id.desc()).first()
    assert f is not None
    assert f.content == ""                       # prose NOT persisted
    assert f.signals                             # but the verdict/signals are
    db.close()
    # the API reports it as not retained
    fid = client.get("/api/findings").json()["findings"][0]["id"]
    detail = client.get(f"/api/findings/{fid}").json()
    assert detail["content"] == "" and detail["content_retained"] is False


def test_opt_in_stores_encrypted_per_tenant(client, raw_client, db_factory, monkeypatch):
    monkeypatch.setattr(service.settings, "store_content", False)
    monkeypatch.setattr(service.settings, "encrypt_findings", True)
    client.patch("/api/tenant", json={"store_content": "on"})     # this tenant opts in
    _ingest_leak(client, raw_client, "confidential roadmap details here")
    db = db_factory()
    f = db.query(Finding).order_by(Finding.id.desc()).first()
    t = db.query(Tenant).filter(Tenant.id == f.tenant_id).first()
    assert f.content.startswith("enc:v2:")       # per-tenant envelope, not plaintext
    assert t.dek_wrapped                          # tenant got its own wrapped key
    assert "confidential roadmap" not in f.content
    db.close()
    # admin can still read it back (decrypted via the tenant DEK)
    fid = client.get("/api/findings").json()["findings"][0]["id"]
    detail = client.get(f"/api/findings/{fid}").json()
    assert "confidential roadmap" in detail["content"] and detail["content_retained"] is True


def test_entropy_redaction_masks_novel_secret(monkeypatch):
    from app.redaction import redact_text
    # a random-looking token that matches no known pattern
    novel = "Zx9Kp2Qw7Lm4Rt6Yn1Bv8Cd3Fg5Hj0"
    out = redact_text(f"here is the token {novel} keep it safe")
    assert novel not in out and "redacted" in out


def test_content_ttl_scrub(client, raw_client, db_factory, monkeypatch):
    monkeypatch.setattr(service.settings, "store_content", True)
    monkeypatch.setattr(service.settings, "encrypt_findings", False)
    monkeypatch.setattr(service.settings, "content_ttl_days", 30)
    _ingest_leak(client, raw_client, "some retained content AKIA4YTGH2NBQF7XZP3K")
    db = db_factory()
    f = db.query(Finding).order_by(Finding.id.desc()).first()
    assert f.content   # stored
    # age it past the TTL
    from datetime import datetime, timedelta, timezone
    f.created_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40)
    db.commit()
    n = service.scrub_expired_content(db)
    assert n >= 1
    db.refresh(f)
    assert f.content == ""    # prose scrubbed, finding kept
    assert f.severity        # metadata intact
    db.close()
