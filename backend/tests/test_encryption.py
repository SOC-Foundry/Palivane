"""Content encryption at rest (WARDEN_ENCRYPT_FINDINGS): DB holds ciphertext, reads decrypt."""

from __future__ import annotations

import app.main as main
from app.crypto import seal, unseal
from app.models import Finding


def test_seal_unseal_roundtrip_and_passthrough():
    s = seal("prompt with AKIAIOSFODNN7EXAMPLE")
    assert s.startswith("enc:v1:") and unseal(s) == "prompt with AKIAIOSFODNN7EXAMPLE"
    assert seal("") == "" and unseal("") == ""
    assert unseal("plaintext row") == "plaintext row"   # legacy/plaintext untouched


def _persist(client, content):
    client.post("/api/analyze", json={"content": content, "surface": "llm_io", "persist": True})
    return client.get("/api/findings").json()["findings"][0]["id"]


def test_stored_content_is_ciphertext_but_reads_decrypt(client, db_factory, monkeypatch):
    monkeypatch.setattr(main.settings, "encrypt_findings", True)
    monkeypatch.setattr(main.settings, "redact_findings", False)   # isolate encryption
    monkeypatch.setattr(main.settings, "store_content", True)
    fid = _persist(client, "please summarize this internal memo")

    # Raw DB value is sealed ciphertext...
    db = db_factory()
    raw = db.get(Finding, fid).content
    db.close()
    assert raw.startswith("enc:") and "summarize" not in raw

    # ...but the detail endpoint returns the plaintext to the authorized admin.
    detail = client.get(f"/api/findings/{fid}").json()
    assert detail["content"] == "please summarize this internal memo"


def test_off_by_default_stores_plaintext(client, db_factory, monkeypatch):
    monkeypatch.setattr(main.settings, "encrypt_findings", False)
    monkeypatch.setattr(main.settings, "redact_findings", False)
    monkeypatch.setattr(main.settings, "store_content", True)
    fid = _persist(client, "hello world")
    db = db_factory()
    assert db.get(Finding, fid).content == "hello world"
    db.close()


def test_redact_then_encrypt_compose(client, db_factory, monkeypatch):
    monkeypatch.setattr(main.settings, "redact_findings", True)
    monkeypatch.setattr(main.settings, "encrypt_findings", True)
    monkeypatch.setattr(main.settings, "store_content", True)
    fid = _persist(client, "key AKIAIOSFODNN7EXAMPLE here")
    db = db_factory()
    raw = db.get(Finding, fid).content
    db.close()
    assert raw.startswith("enc:")
    # Decrypted view is the redacted content (secret masked), not the raw key.
    detail = client.get(f"/api/findings/{fid}").json()
    assert "AKIAIOSFODNN7EXAMPLE" not in detail["content"] and "«redacted:" in detail["content"]