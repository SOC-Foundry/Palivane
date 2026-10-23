"""Opt-in OCR for image DLP (PALIVANE_OCR=true).

Prompts increasingly carry screenshots — and screenshots carry secrets and PII that the
text-only scan never sees. When enabled, the gateway extracts base64 image payloads from
the provider request shapes (Anthropic `source.data`, OpenAI `image_url` data: URIs,
Gemini `inline_data`), OCRs them, and appends the recovered text to the scanned content.

Soft dependency: requires Pillow + pytesseract (and the tesseract binary) at runtime.
Everything here is best-effort and fail-open — if OCR is unavailable or an image is
malformed, the gateway behaves exactly as if the feature were off: the request goes through
and its verdict is marked partly scanned (images unread), never blocked. OCR text is only fed
to the detector pipeline; it is never stored beyond normal finding evidence.
"""

from __future__ import annotations

import base64
import shutil
import time
from typing import NamedTuple

_MAX_IMAGE_BYTES = 5_000_000   # skip anything bigger (~5MB) — OCR cost, DoS guard
_MAX_COLLECTED = 8             # cap images harvested from one request body
# OCR runs in the request path, so its cost is bounded three ways (an image any of them
# stops is unread: a partial-scan marker, never a block):
#   _MAX_PIXELS     checked from the header before decoding. pytesseract decodes and
#                   re-encodes the image in-process before tesseract starts, which the
#                   timeout below does not cover; 16 MP still admits a 5K/retina screenshot.
#   _OCR_TIMEOUT_S  per tesseract call; pytesseract kills the process when it runs over.
#                   A full-screen 1080p screenshot of dense text takes ~2 s on one core.
#   _OCR_BUDGET_S   per call to read_images (one request): later images get what is left,
#                   and none once it is spent. 4 images x 5 s could otherwise be 20 s.
_MAX_PIXELS = 16_000_000
_OCR_TIMEOUT_S = 5.0
_OCR_BUDGET_S = 10.0

_available: bool | None = None  # cached probe result


def ocr_available() -> bool:
    """True when Pillow + pytesseract are importable AND the tesseract binary is on PATH
    (lazily probed once per process). The Python packages ship in every install; the binary
    only where it was installed (the Cloud Run/compose image does), so without this check a
    native install would try, and fail, every image and call it unreadable rather than off."""
    global _available
    if _available is None:
        try:
            import PIL.Image  # noqa: F401
            import pytesseract
            _available = shutil.which(pytesseract.pytesseract.tesseract_cmd) is not None
        except Exception:
            _available = False
    return _available


def ocr_enabled() -> bool:
    """OCR switched on for this deployment (PALIVANE_OCR) and able to run. Every caller that
    reads images goes through this, so installing the packages never turns OCR on by itself."""
    from .config import settings
    return bool(settings.gateway_ocr) and ocr_available()


class ImageText(NamedTuple):
    """What OCR got out of a set of images: the text, and how many images it came from.
    `read < present` means some images went unread (too big, past `max_images`, an OCR
    error, blank OCR, OCR unavailable), which the caller must surface rather than call clean."""
    text: str
    present: int   # images handed in
    read: int      # images whose text made it into `text`


def read_images(images: list[bytes], max_images: int = 4, max_chars: int = 8000) -> ImageText:
    """OCR each image and join the non-empty text, counting the images it read. Never
    raises — any failure (missing deps, undecodable image, tesseract error or timeout)
    contributes nothing; oversized images (bytes or pixels) are skipped, and so is every
    image after the time budget is spent. Output is capped at max_chars, and an image whose
    text the cap cut short does not count as read."""
    present = len(images or [])
    if not present or not ocr_available():
        return ImageText("", present, 0)
    try:
        import io

        import PIL.Image
        import pytesseract
    except Exception:
        return ImageText("", present, 0)
    parts: list[str] = []
    read = used = 0
    deadline = time.monotonic() + _OCR_BUDGET_S
    for raw in images[:max_images]:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) > _MAX_IMAGE_BYTES:
            continue
        left = deadline - time.monotonic()
        if left <= 0:
            break                       # budget spent: the rest stay unread
        try:
            with PIL.Image.open(io.BytesIO(raw)) as img:
                width, height = img.size     # from the header; nothing decoded yet
                if width * height > _MAX_PIXELS:
                    continue
                # timeout=0 would mean "no timeout" to pytesseract; `left` is > 0 here.
                text = pytesseract.image_to_string(img, timeout=min(_OCR_TIMEOUT_S, left))
        except Exception:               # includes RuntimeError("Tesseract process timeout")
            continue
        text = (text or "").strip()
        if text:
            parts.append(text)
            used += len(text) + (len(parts) > 1)   # + the joining newline
            read += used <= max_chars
    return ImageText("\n".join(parts)[:max_chars], present, read)


def extract_image_text(images: list[bytes], max_images: int = 4, max_chars: int = 8000) -> str:
    """read_images' text alone, for callers that judge "unread" by the text being empty."""
    return read_images(images, max_images=max_images, max_chars=max_chars).text


def _b64(data: str) -> bytes | None:
    try:
        return base64.b64decode(data, validate=False)
    except Exception:
        return None


def collect_images(body: dict) -> list[bytes]:
    """Walk an arbitrary request body and collect decoded base64 image payloads from the
    three provider shapes:

      Anthropic:  {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                   "data": "..."}}
      OpenAI:     {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
                  (the url may also be a bare string, as in Responses
                  {"type": "input_image", "image_url": "data:image/png;base64,..."})
      Gemini:     {"inline_data": {"mime_type": "image/png", "data": "..."}}  (or inlineData)

    Capped at 8 images; anything undecodable is skipped."""
    out: list[bytes] = []

    def _add(decoded: bytes | None) -> None:
        if decoded:
            out.append(decoded)

    def _walk(node) -> None:
        if len(out) >= _MAX_COLLECTED:
            return
        if isinstance(node, dict):
            # Anthropic image block: source.data with an image/* media_type.
            src = node.get("source")
            if isinstance(src, dict) and isinstance(src.get("data"), str) \
                    and str(src.get("media_type", "")).startswith("image/"):
                _add(_b64(src["data"]))
            # OpenAI image_url part: data:image/...;base64,<payload> URI.
            iu = node.get("image_url")
            url = iu.get("url") if isinstance(iu, dict) else iu
            if isinstance(url, str) and url.startswith("data:image/"):
                _, _, payload = url.partition(",")
                if payload:
                    _add(_b64(payload))
            # Gemini inline_data / inlineData part with an image/* mime_type.
            inline = node.get("inline_data") or node.get("inlineData")
            if isinstance(inline, dict) and isinstance(inline.get("data"), str) \
                    and str(inline.get("mime_type") or inline.get("mimeType") or "").startswith("image/"):
                _add(_b64(inline["data"]))
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(body if isinstance(body, dict) else {})
    return out[:_MAX_COLLECTED]
