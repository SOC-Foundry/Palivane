"""Opt-in OCR image DLP (PALIVANE_OCR): image collection across the three provider shapes,
graceful degradation without pytesseract, and the gateway hook end-to-end."""

from __future__ import annotations

import base64
import sys

from app import ocr

PNG_FAKE = b"\x89PNG-fake-image-bytes"


def _b64(data: bytes = PNG_FAKE) -> str:
    return base64.b64encode(data).decode()


# --- collect_images: the three provider body shapes -----------------------------------

def test_collect_images_anthropic():
    body = {"model": "claude-sonnet-4-6", "messages": [
        {"role": "user", "content": [
            {"type": "text", "text": "what does this say?"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                         "data": _b64()}},
        ]}]}
    assert ocr.collect_images(body) == [PNG_FAKE]


def test_collect_images_openai_data_uri():
    body = {"model": "gpt-4o", "messages": [
        {"role": "user", "content": [
            {"type": "text", "text": "read this"},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{_b64()}"}},
        ]}]}
    assert ocr.collect_images(body) == [PNG_FAKE]
    # Bare-string image_url variant.
    body2 = {"messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": f"data:image/jpeg;base64,{_b64()}"}]}]}
    assert ocr.collect_images(body2) == [PNG_FAKE]
    # Remote (non-data:) URLs are not fetched.
    body3 = {"messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}}]}]}
    assert ocr.collect_images(body3) == []


def test_collect_images_gemini():
    body = {"contents": [{"role": "user", "parts": [
        {"text": "describe"},
        {"inline_data": {"mime_type": "image/png", "data": _b64()}},
    ]}]}
    assert ocr.collect_images(body) == [PNG_FAKE]
    # camelCase variant (Gemini REST JSON).
    body2 = {"contents": [{"parts": [
        {"inlineData": {"mimeType": "image/webp", "data": _b64()}}]}]}
    assert ocr.collect_images(body2) == [PNG_FAKE]
    # Non-image inline_data (e.g. a PDF) is skipped.
    body3 = {"contents": [{"parts": [
        {"inline_data": {"mime_type": "application/pdf", "data": _b64()}}]}]}
    assert ocr.collect_images(body3) == []


def test_collect_images_caps_at_eight():
    blocks = [{"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                           "data": _b64()}} for _ in range(12)]
    body = {"messages": [{"role": "user", "content": blocks}]}
    assert len(ocr.collect_images(body)) == 8


def test_collect_images_ignores_non_image_and_garbage():
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "base64", "media_type": "application/pdf",
                                        "data": _b64()}},   # Anthropic doc block: not an image
        {"type": "text", "text": "hello"},
    ]}], "weird": [1, None, "str", {"nested": {"deep": True}}]}
    assert ocr.collect_images(body) == []
    assert ocr.collect_images("not a dict") == []  # type: ignore[arg-type]


# --- extract_image_text: graceful without pytesseract ----------------------------------

def test_extract_image_text_graceful_when_pytesseract_missing(monkeypatch):
    monkeypatch.setattr(ocr, "_available", None)          # reset the cached probe
    monkeypatch.setitem(sys.modules, "pytesseract", None)  # make `import pytesseract` fail
    assert ocr.ocr_available() is False
    assert ocr.extract_image_text([PNG_FAKE]) == ""


def test_extract_image_text_empty_input():
    assert ocr.extract_image_text([]) == ""


# --- Gateway hook: /v1/messages with an image-only prompt ------------------------------

IMAGE_ONLY = {"model": "claude-sonnet-4-6", "max_tokens": 64, "messages": [
    {"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                     "data": _b64()}}]}]}


def _token(client):
    return client.headers["Authorization"].split(" ", 1)[1]


def _fake_ocr(monkeypatch):
    """Simulate a working OCR stack that reads an SSN out of any collected image."""
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(
        ocr, "extract_image_text",
        lambda imgs, **kw: "employee record\nssn is 123-45-6789" if imgs else "")


def test_messages_image_ssn_flagged_when_ocr_on(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)  # monitor mode
    monkeypatch.setattr(gateway.settings, "gateway_ocr", True)
    _fake_ocr(monkeypatch)

    r = client.post("/v1/messages", json=IMAGE_ONLY,
                    headers={"x-api-key": _token(client), "Authorization": ""})
    # A confirmed PII leak (dashed SSN) hard-blocks even under monitor mode
    # (gateway_enforce_secrets default) — proof the OCR text reached the scanner.
    assert r.status_code == 400
    assert "Blocked by Palivane" in r.json()["error"]["message"]

    findings = client.get("/api/findings").json()["findings"]
    assert any(f["surface"] == "llm_io" and "pii_exposure" in f["categories"]
               for f in findings)


def test_messages_image_noop_when_ocr_off(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_ocr", False)      # default: off
    called = []
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(ocr, "extract_image_text",
                        lambda imgs, **kw: called.append(1) or "ssn is 123-45-6789")

    r = client.post("/v1/messages", json=IMAGE_ONLY,
                    headers={"x-api-key": _token(client), "Authorization": ""})
    assert r.status_code == 200
    assert r.json()["warden"]["severity"] in ("benign", "low")
    assert not called                                                 # OCR never invoked
