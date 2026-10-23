"""Opt-in OCR image DLP (PALIVANE_OCR): image collection across the three provider shapes,
graceful degradation without pytesseract, and the gateway hook end-to-end."""

from __future__ import annotations

import base64
import io
import shutil
import sys

import pytest

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
        ocr, "read_images",
        lambda imgs, **kw: ocr.ImageText("employee record\nssn is 123-45-6789" if imgs else "",
                                         len(imgs), len(imgs)))


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


def test_collect_images_responses_input_image():
    body = {"model": "gpt-5-codex", "input": [{"role": "user", "content": [
        {"type": "input_text", "text": "read this"},
        {"type": "input_image", "image_url": f"data:image/png;base64,{_b64()}"}]}]}
    assert ocr.collect_images(body) == [PNG_FAKE]


def test_responses_image_ssn_flagged_when_ocr_on(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)  # monitor mode
    monkeypatch.setattr(gateway.settings, "gateway_ocr", True)
    _fake_ocr(monkeypatch)
    body = {"model": "gpt-5-codex", "input": [
        {"type": "input_image", "image_url": f"data:image/png;base64,{_b64()}"}]}
    r = client.post("/v1/responses", json=body)
    # Confirmed PII hard-blocks even under monitor — the OCR text reached the scanner.
    assert r.status_code == 403
    assert r.json()["error"]["type"] == "palivane_blocked"
    findings = client.get("/api/findings").json()["findings"]
    assert any(f["surface"] == "llm_io" and "pii_exposure" in f["categories"]
               for f in findings)


def test_messages_image_noop_when_ocr_off(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_ocr", False)      # default: off
    called = []
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(ocr, "read_images",
                        lambda imgs, **kw: called.append(1) or ocr.ImageText("ssn is 123-45-6789", 1, 1))

    r = client.post("/v1/messages", json=IMAGE_ONLY,
                    headers={"x-api-key": _token(client), "Authorization": ""})
    assert r.status_code == 200
    assert r.json()["palivane"]["severity"] in ("benign", "low")
    assert not called                                                 # OCR never invoked


# --- Unread images: a partial-scan marker, never a clean verdict (SEC-02) ---------------
# The real read_images over a fake Pillow + tesseract: an image's bytes say what it OCRs to.

class _FakeImg:
    size = (800, 600)

    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_tesseract(monkeypatch):
    """b"ERR..." raises in tesseract, b"BLANK..." OCRs to nothing, anything else to its bytes."""
    import types

    def image_to_string(img, timeout=0):
        if img.raw.startswith(b"ERR"):
            raise RuntimeError("tesseract failed")
        if img.raw.startswith(b"SLOW"):
            raise RuntimeError("Tesseract process timeout")   # what pytesseract raises
        return "" if img.raw.startswith(b"BLANK") else img.raw.decode()

    image_mod = types.SimpleNamespace(open=lambda buf: _FakeImg(buf.getvalue()))
    monkeypatch.setitem(sys.modules, "PIL", types.SimpleNamespace(Image=image_mod))
    monkeypatch.setitem(sys.modules, "PIL.Image", image_mod)
    monkeypatch.setitem(sys.modules, "pytesseract",
                        types.SimpleNamespace(image_to_string=image_to_string))
    monkeypatch.setattr(ocr, "_available", True)


def test_read_images_counts_what_it_read(monkeypatch):
    _fake_tesseract(monkeypatch)
    assert ocr.read_images([b"one", b"two"]) == ("one\ntwo", 2, 2)
    big = b"x" * (ocr._MAX_IMAGE_BYTES + 1)
    assert ocr.read_images([b"one", big]) == ("one", 2, 1)                  # over 5 MB
    assert ocr.read_images([b"a", b"b", b"c", b"d", b"e"]).read == 4        # past the four
    assert ocr.read_images([b"one", b"ERR"]) == ("one", 2, 1)               # tesseract error
    assert ocr.read_images([b"BLANK"]) == ("", 1, 0)                        # blank OCR
    # Text the max_chars cap cut short is not "read".
    assert ocr.read_images([b"aaaa", b"bbbb"], max_chars=6) == ("aaaa\nb", 2, 1)
    # The str API the connectors use is unchanged.
    assert ocr.extract_image_text([b"one", b"ERR"]) == "one"


def test_read_images_without_ocr_reads_none(monkeypatch):
    monkeypatch.setattr(ocr, "_available", False)
    assert ocr.read_images([PNG_FAKE, PNG_FAKE]) == ("", 2, 0)
    assert ocr.read_images([]) == ("", 0, 0)


def _anthropic_images(*raws: bytes) -> dict:
    return {"model": "claude-sonnet-4-6", "max_tokens": 64, "messages": [
        {"role": "user", "content": [{"type": "text", "text": "what do these say?"}] + [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                         "data": _b64(r)}} for r in raws]}]}


def _verdicts(monkeypatch) -> list[dict]:
    """Record every verdict the gateway's analysis returns."""
    from app import gateway
    seen: list[dict] = []
    real = gateway.run_analysis

    def spy(*a, **kw):
        seen.append(real(*a, **kw))
        return seen[-1]

    monkeypatch.setattr(gateway, "run_analysis", spy)
    return seen


def _post_messages(client, body):
    return client.post("/v1/messages", json=body,
                       headers={"x-api-key": _token(client), "Authorization": ""})


def _markers(verdict: dict) -> list[dict]:
    return [s for s in verdict["signals"] if s["check"] == "detector_error"]


def _ocr_on(monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_ocr", True)
    _fake_tesseract(monkeypatch)


def test_oversized_image_marks_partial_scan(client, monkeypatch):
    _ocr_on(monkeypatch)
    seen = _verdicts(monkeypatch)
    big = b"x" * (ocr._MAX_IMAGE_BYTES + 1)
    r = _post_messages(client, _anthropic_images(b"hello there", big))
    assert r.status_code == 200                           # recorded, never blocked
    v = seen[0]
    assert v["unscanned"] == ["image"]
    [m] = _markers(v)
    assert m["evidence"] == "image=1 of 2 unread" and m["weight"] == 0


def test_fifth_image_past_the_ocr_cap_marks_partial_scan(client, monkeypatch):
    _ocr_on(monkeypatch)
    seen = _verdicts(monkeypatch)
    _post_messages(client, _anthropic_images(b"a1", b"b2", b"c3", b"d4", b"e5"))
    assert seen[0]["unscanned"] == ["image"]
    assert _markers(seen[0])[0]["evidence"] == "image=1 of 5 unread"


def test_tesseract_error_marks_partial_scan(client, monkeypatch):
    _ocr_on(monkeypatch)
    seen = _verdicts(monkeypatch)
    _post_messages(client, _anthropic_images(b"ERR"))
    assert seen[0]["unscanned"] == ["image"]
    assert _markers(seen[0])[0]["evidence"] == "image=1 of 1 unread"


def test_all_images_read_no_marker(client, monkeypatch):
    _ocr_on(monkeypatch)
    seen = _verdicts(monkeypatch)
    _post_messages(client, _anthropic_images(b"first page", b"second page"))
    assert "unscanned" not in seen[0] and not _markers(seen[0])


def test_no_image_no_marker(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_ocr", False)   # even with OCR off
    seen = _verdicts(monkeypatch)
    _post_messages(client, {"model": "claude-sonnet-4-6", "max_tokens": 64,
                            "messages": [{"role": "user", "content": "hello"}]})
    assert "unscanned" not in seen[0] and not _markers(seen[0])


def test_ocr_off_marks_once_per_request(client, monkeypatch):
    # OCR off (the default) or not installed: the images were not inspected at all, so the
    # verdict says so: one marker for the request however many images, and still no block.
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_enforce", True)
    monkeypatch.setattr(gateway.settings, "gateway_ocr", False)
    seen = _verdicts(monkeypatch)
    r = _post_messages(client, _anthropic_images(*[b"img"] * 12))
    assert r.status_code == 200
    [m] = _markers(seen[0])
    assert m["evidence"] == "image=8 of 8+ unread"          # collect_images stops at 8
    assert "OCR" in m["detail"] and "is off" in m["detail"]
    assert seen[0]["severity"] in ("benign", "low")
    # pytesseract missing reads the same as the setting being off.
    monkeypatch.setattr(gateway.settings, "gateway_ocr", True)
    monkeypatch.setattr(ocr, "_available", False)
    _post_messages(client, _anthropic_images(b"img"))
    assert _markers(seen[1])[0]["evidence"] == "image=1 of 1 unread"


def test_marker_never_lowers_or_raises_the_verdict(client, monkeypatch):
    # The SSN in the image that WAS read still hard-blocks; the unread one adds a marker only.
    _ocr_on(monkeypatch)
    seen = _verdicts(monkeypatch)
    r = _post_messages(client, _anthropic_images(b"ssn is 123-45-6789", b"ERR"))
    assert r.status_code == 400
    assert seen[0]["unscanned"] == ["image"]
    assert "pii_exposure" in {s["category"] for s in seen[0]["signals"]}


def test_marker_on_every_route(client, monkeypatch):
    _ocr_on(monkeypatch)
    seen = _verdicts(monkeypatch)
    uri = f"data:image/png;base64,{_b64(b'ERR')}"
    client.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": [
        {"role": "user", "content": [{"type": "text", "text": "read"},
                                     {"type": "image_url", "image_url": {"url": uri}}]}]})
    client.post("/v1/responses", json={"model": "gpt-5-codex", "input": [
        {"type": "input_image", "image_url": uri}]})
    _post_messages(client, _anthropic_images(b"ERR"))
    client.post("/v1beta/models/gemini-2.5-flash:generateContent", json={"contents": [
        {"role": "user", "parts": [{"text": "read"},
                                   {"inline_data": {"mime_type": "image/png",
                                                    "data": _b64(b"ERR")}}]}]},
                headers={"x-goog-api-key": _token(client), "Authorization": ""})
    marked = [v for v in seen if _markers(v)]
    assert len(marked) == 4
    assert all(v["unscanned"] == ["image"] for v in marked)


def test_marker_does_not_split_the_recurrence_fingerprint(client, monkeypatch):
    # The same leak with and without an unread image folds into one event.
    _ocr_on(monkeypatch)
    _post_messages(client, _anthropic_images(b"ssn is 123-45-6789"))
    _post_messages(client, _anthropic_images(b"ssn is 123-45-6789", b"ERR"))
    findings = [f for f in client.get("/api/findings").json()["findings"]
                if "pii_exposure" in f["categories"]]
    assert len(findings) == 1


# --- Bounded cost: OCR runs in the request path ----------------------------------------

def test_a_tesseract_timeout_is_an_unread_image(monkeypatch):
    _fake_tesseract(monkeypatch)
    assert ocr.read_images([b"one", b"SLOW"]) == ("one", 2, 1)


def test_every_tesseract_call_is_timed_and_the_request_has_a_budget(monkeypatch):
    _fake_tesseract(monkeypatch)
    timeouts: list[float] = []
    clock = [1000.0]

    def image_to_string(img, timeout=0):
        timeouts.append(timeout)
        clock[0] += 4.0                       # every image takes 4 s of the budget
        return img.raw.decode()

    monkeypatch.setattr(sys.modules["pytesseract"], "image_to_string", image_to_string)
    monkeypatch.setattr(ocr.time, "monotonic", lambda: clock[0])
    got = ocr.read_images([b"a", b"b", b"c", b"d"])
    # 10 s budget: 5 (per-image cap), 5, then the 2 s left; the fourth is never attempted.
    assert timeouts == [ocr._OCR_TIMEOUT_S, ocr._OCR_TIMEOUT_S, 2.0]
    assert all(t > 0 for t in timeouts)       # timeout=0 means "none" to pytesseract
    assert got == ("a\nb\nc", 4, 3)


def test_an_image_over_the_pixel_cap_is_never_decoded(monkeypatch):
    _fake_tesseract(monkeypatch)
    called = []
    monkeypatch.setattr(sys.modules["pytesseract"], "image_to_string",
                        lambda img, timeout=0: called.append(1) or "text")
    monkeypatch.setattr(_FakeImg, "size", (8000, 8000))      # 64 MP, a few KB of PNG
    assert ocr.read_images([b"huge"]) == ("", 1, 0)
    assert not called


def test_a_tesseract_timeout_marks_partial_scan_and_never_blocks(client, monkeypatch):
    from app import gateway
    _ocr_on(monkeypatch)
    monkeypatch.setattr(gateway.settings, "gateway_enforce", True)
    seen = _verdicts(monkeypatch)
    r = _post_messages(client, _anthropic_images(b"hello there", b"SLOW"))
    assert r.status_code == 200
    assert seen[0]["unscanned"] == ["image"]
    assert _markers(seen[0])[0]["evidence"] == "image=1 of 2 unread"


# --- PALIVANE_OCR gates every reader, not just the gateway ------------------------------

def test_installed_but_switched_off_reads_nothing(monkeypatch):
    """The packages ship in every install; the setting is what turns OCR on."""
    from app.config import settings
    from app.doc_extract import extract
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(ocr, "extract_image_text", lambda *a, **k: "key AKIA4YTGH2NBQF7XZP3K")
    monkeypatch.setattr(settings, "gateway_ocr", False)
    assert not ocr.ocr_enabled()
    assert extract("shot.png", b"\x89PNG\r\n\x1a\n") == ("", "")
    monkeypatch.setattr(settings, "gateway_ocr", True)
    assert ocr.ocr_enabled()


def test_no_tesseract_binary_means_unavailable(monkeypatch):
    pytest.importorskip("pytesseract")
    pytest.importorskip("PIL.Image")
    monkeypatch.setattr(ocr, "_available", None)
    monkeypatch.setattr(ocr.shutil, "which", lambda cmd: None)
    assert ocr.ocr_available() is False


# --- The real thing: Pillow + pytesseract + tesseract with English data -----------------
# Runs where tesseract is installed (the production image has it); skipped elsewhere.

def _real_tesseract() -> bool:
    try:
        import PIL.Image  # noqa: F401
        import pytesseract
        return bool(shutil.which(pytesseract.pytesseract.tesseract_cmd)) \
            and "eng" in pytesseract.get_languages(config="")
    except Exception:
        return False


needs_tesseract = pytest.mark.skipif(
    not _real_tesseract(), reason="needs Pillow + pytesseract + tesseract with English data")

AWS_KEY = "AKIA4YTGH2NBWF7XZP3K"   # no O/0/Q/I/1 lookalikes for OCR to trip on


def _screenshot(text: str) -> bytes:
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (900, 120), "white")
    ImageDraw.Draw(img).text((20, 40), text, fill="black", font=ImageFont.load_default(size=32))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


@needs_tesseract
def test_real_ocr_reads_an_aws_key_out_of_a_png(monkeypatch):
    monkeypatch.setattr(ocr, "_available", None)
    got = ocr.read_images([_screenshot(f"aws_access_key_id = {AWS_KEY}")])
    assert got.read == 1 and AWS_KEY in got.text.replace(" ", "")


@needs_tesseract
def test_real_ocr_catches_the_key_through_the_gateway(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(ocr, "_available", None)
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)     # monitor mode
    monkeypatch.setattr(gateway.settings, "gateway_ocr", True)
    seen = _verdicts(monkeypatch)
    r = _post_messages(client, _anthropic_images(_screenshot(f"export AWS_ACCESS_KEY_ID={AWS_KEY}")))
    # A confirmed credential hard-blocks even in monitor mode — only reachable through OCR.
    assert r.status_code == 400
    assert "secret_leak" in {s["category"] for s in seen[0]["signals"]}
    assert "unscanned" not in seen[0]


@needs_tesseract
def test_real_tesseract_timeout_is_unread_not_blocked(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(ocr, "_available", None)
    monkeypatch.setattr(ocr, "_OCR_TIMEOUT_S", 0.001)        # tesseract cannot start in 1 ms
    monkeypatch.setattr(gateway.settings, "gateway_enforce", True)
    monkeypatch.setattr(gateway.settings, "gateway_ocr", True)
    seen = _verdicts(monkeypatch)
    r = _post_messages(client, _anthropic_images(_screenshot(f"key {AWS_KEY}")))
    assert r.status_code == 200
    assert seen[0]["unscanned"] == ["image"]
    assert _markers(seen[0])[0]["evidence"] == "image=1 of 1 unread"
