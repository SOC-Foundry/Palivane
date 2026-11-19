"""Files and screenshots captured by the browser extension (POST /api/ingest/ai-attachment).

The bytes are turned into text by the same extractor the at-rest scanners use, images by
the OCR path, and that text is scored like a prompt: the same block, the same confirmed-leak
hard block, and a fail-open allow when the file cannot be read.
"""
from __future__ import annotations

import base64

from app.config import settings

SSN = "Patient Jane Doe, SSN 123-45-6789, diagnosed with type 2 diabetes"
CONFIDENTIAL = "COMPANY CONFIDENTIAL\nDo not distribute.\nQ3 payroll file for the board."
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def _key(client) -> str:
    return client.post("/api/apikeys", json={"label": "ext", "actor": "dev@acme.com"}).json()["token"]


def _post(raw_client, key, **body):
    return raw_client.post("/api/ingest/ai-attachment", json=body,
                           headers={"X-Palivane-Token": key})


def test_requires_a_capture_key(raw_client):
    r = raw_client.post("/api/ingest/ai-attachment",
                        json={"filename": "n.txt", "data_b64": base64.b64encode(b"hi").decode()})
    assert r.status_code == 401


def test_a_text_file_with_an_ssn_blocks_like_a_prompt(client, raw_client):
    r = _post(raw_client, _key(client), filename="notes.txt", mime="text/plain",
              data_b64=base64.b64encode(SSN.encode()).decode(),
              destination="https://chatgpt.com", endpoint="chatgpt.com/backend-api/files")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["attachment"] is True and body["action"] == "block" and body["force_block"] is True
    assert "pii_exposure" in {s["category"] for s in body["signals"]}
    assert body["finding_id"]
    # The filename is what a reviewer sees. The matched value is not the subject.
    finding = client.get(f"/api/findings/{body['finding_id']}").json()
    assert finding["subject"] == "attachment: notes.txt"
    assert "123-45-6789" not in (finding.get("subject") or "")


def test_a_path_in_the_filename_is_stripped(client, raw_client):
    r = _post(raw_client, _key(client), filename="../../secrets.txt", mime="text/plain",
              data_b64=base64.b64encode(SSN.encode()).decode(), destination="https://claude.ai")
    body = r.json()
    assert body["action"] == "block"
    finding = client.get(f"/api/findings/{body['finding_id']}").json()
    assert finding["subject"] == "attachment: secrets.txt"


def test_confidential_prose_in_a_file_is_the_same_detector(client, raw_client):
    r = _post(raw_client, _key(client), filename="board.txt", mime="text/plain",
              data_b64=base64.b64encode(CONFIDENTIAL.encode()).decode(),
              destination="https://gemini.google.com")
    assert r.status_code == 200, r.text
    cats = {s["category"] for s in r.json()["signals"]}
    assert "confidential_data" in cats
    assert r.json()["action"] in ("warn", "block")


def test_an_image_is_unread_and_allowed_when_ocr_is_off(client, raw_client, monkeypatch):
    monkeypatch.setattr(settings, "gateway_ocr", False)
    r = _post(raw_client, _key(client), filename="shot.png", mime="image/png",
              data_b64=base64.b64encode(PNG).decode(), destination="https://chatgpt.com")
    body = r.json()
    assert body["action"] == "allow" and body["force_block"] is False
    assert body["unread"] == "image" and body["partial"] is True
    assert body["signals"] == []


def test_an_image_with_an_ssn_blocks_when_ocr_is_on(client, raw_client, monkeypatch):
    from app import ocr
    monkeypatch.setattr(settings, "gateway_ocr", True)
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(ocr, "extract_image_text", lambda imgs, **kw: "ssn is 123-45-6789" if imgs else "")
    r = _post(raw_client, _key(client), filename="shot.png", mime="image/png",
              data_b64=base64.b64encode(PNG).decode(), destination="https://claude.ai")
    body = r.json()
    assert body["action"] == "block" and body["force_block"] is True
    assert body["extract"] == "ocr"
    assert "pii_exposure" in {s["category"] for s in body["signals"]}


def test_an_unreadable_format_fails_open(client, raw_client):
    r = _post(raw_client, _key(client), filename="legacy.doc", mime="application/msword",
              data_b64=base64.b64encode(b"\xd0\xcf\x11\xe0").decode(),
              destination="https://gemini.google.com")
    body = r.json()
    assert body["action"] == "allow" and body["unread"] == "unreadable" and body["partial"] is True


def test_a_file_over_five_megabytes_is_not_blocked(client, raw_client):
    raw = b"x" * (5_000_001)
    r = _post(raw_client, _key(client), filename="big.txt", mime="text/plain",
              data_b64=base64.b64encode(raw).decode(), destination="https://chatgpt.com")
    assert r.status_code == 200, r.text
    assert r.json()["action"] == "allow" and r.json()["unread"] == "too_large"
