"""Redaction of secrets/PII from stored finding content (PALIVANE_REDACT_FINDINGS)."""

from __future__ import annotations

import app.main as main
from app.redaction import redact_text


def test_redacts_secrets_ssn_and_cards():
    out = redact_text("key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789 card 4111 1111 1111 1111")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "123-45-6789" not in out
    assert "4111 1111 1111 1111" not in out
    assert "«redacted:" in out


def test_leaves_benign_text_intact():
    assert redact_text("Summarize this quarterly report, please.") == \
        "Summarize this quarterly report, please."


def test_invalid_card_not_redacted():
    # Non-Luhn 16-digit run is left alone (not a real card).
    assert "1234 5678 9012 3456" in redact_text("order 1234 5678 9012 3456")


def test_stored_finding_content_is_redacted(client, raw_client, monkeypatch):
    monkeypatch.setattr(main.settings, "redact_findings", True)
    monkeypatch.setattr(main.settings, "store_content", True)
    key = client.post("/api/apikeys", json={"label": "cap", "actor": "x@acme.com"}).json()["token"]
    raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "deploy with AKIAIOSFODNN7EXAMPLE and SSN 123-45-6789",
              "destination": "https://chat.openai.com/"},
        headers={"X-Palivane-Token": key},
    )
    findings = client.get("/api/findings").json()["findings"]
    detail = client.get(f"/api/findings/{findings[0]['id']}").json()
    assert "AKIAIOSFODNN7EXAMPLE" not in detail["content"]
    assert "123-45-6789" not in detail["content"]
    assert "«redacted:" in detail["content"]


def test_redaction_can_be_disabled(client, raw_client, monkeypatch):
    monkeypatch.setattr(main.settings, "redact_findings", False)
    monkeypatch.setattr(main.settings, "store_content", True)
    key = client.post("/api/apikeys", json={"label": "cap2", "actor": "y@acme.com"}).json()["token"]
    raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "raw AKIAIOSFODNN7EXAMPLE kept", "destination": "https://chat.openai.com/"},
        headers={"X-Palivane-Token": key},
    )
    findings = client.get("/api/findings").json()["findings"]
    detail = client.get(f"/api/findings/{findings[0]['id']}").json()
    assert "AKIAIOSFODNN7EXAMPLE" in detail["content"]

def _rsa_pem() -> str:
    # Generated per run so no key material is committed (and the repo's own scanners stay quiet).
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def test_private_key_body_is_redacted_not_just_the_header():
    pem = _rsa_pem()
    out = redact_text(f"here is the deploy key\n{pem}\nthanks")
    body = [ln for ln in pem.splitlines() if ln and not ln.startswith("-----")]
    assert not [ln for ln in body if ln in out]
    assert not any(ln[:16] in out for ln in body)   # no partial line survives either
    assert "END PRIVATE KEY" not in out
    assert out.startswith("here is the deploy key\n«redacted:Private key block»")
    assert out.endswith("thanks")


def test_truncated_private_key_is_redacted_to_the_end():
    pem = _rsa_pem()
    cut = pem[: len(pem) // 2]                        # paste lost its footer
    out = redact_text(f"key: {cut}")
    assert out == "key: «redacted:Private key block»"


def test_pgp_private_key_block_is_redacted():
    out = redact_text("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF+abc/def+ghi\n=XyZ1\n"
                      "-----END PGP PRIVATE KEY BLOCK-----\nafter")
    assert out == "«redacted:Private key block»\nafter"
