"""Redaction of secrets/PII from stored finding content (WARDEN_REDACT_FINDINGS)."""

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
    key = client.post("/api/apikeys", json={"label": "cap", "actor": "x@acme.com"}).json()["token"]
    raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "deploy with AKIAIOSFODNN7EXAMPLE and SSN 123-45-6789",
              "destination": "https://chat.openai.com/"},
        headers={"X-Warden-Token": key},
    )
    findings = client.get("/api/findings").json()["findings"]
    detail = client.get(f"/api/findings/{findings[0]['id']}").json()
    assert "AKIAIOSFODNN7EXAMPLE" not in detail["content"]
    assert "123-45-6789" not in detail["content"]
    assert "«redacted:" in detail["content"]


def test_redaction_can_be_disabled(client, raw_client, monkeypatch):
    monkeypatch.setattr(main.settings, "redact_findings", False)
    key = client.post("/api/apikeys", json={"label": "cap2", "actor": "y@acme.com"}).json()["token"]
    raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "raw AKIAIOSFODNN7EXAMPLE kept", "destination": "https://chat.openai.com/"},
        headers={"X-Warden-Token": key},
    )
    findings = client.get("/api/findings").json()["findings"]
    detail = client.get(f"/api/findings/{findings[0]['id']}").json()
    assert "AKIAIOSFODNN7EXAMPLE" in detail["content"]