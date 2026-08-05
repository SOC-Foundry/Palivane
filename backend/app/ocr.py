"""Opt-in OCR for image DLP (PALIVANE_OCR=true).

Prompts increasingly carry screenshots — and screenshots carry secrets and PII that the
text-only scan never sees. When enabled, the gateway extracts base64 image payloads from
the provider request shapes (Anthropic `source.data`, OpenAI `image_url` data: URIs,
Gemini `inline_data`), OCRs them, and appends the recovered text to the scanned content.

Soft dependency: requires Pillow + pytesseract (and the tesseract binary) at runtime.
Everything here is best-effort and fail-open — if OCR is unavailable or an image is
malformed, the gateway behaves exactly as if the feature were off. OCR text is only fed
to the detector pipeline; it is never stored beyond normal finding evidence.
"""

from __future__ import annotations

import base64

_MAX_IMAGE_BYTES = 5_000_000   # skip anything bigger (~5MB) — OCR cost, DoS guard
_MAX_COLLECTED = 8             # cap images harvested from one request body

_available: bool | None = None  # cached probe result


def ocr_available() -> bool:
    """True when Pillow + pytesseract are importable (lazily probed once per process)."""
    global _available
    if _available is None:
        try:
            import PIL.Image  # noqa: F401
            import pytesseract  # noqa: F401
            _available = True
        except Exception:
            _available = False
    return _available


def extract_image_text(images: list[bytes], max_images: int = 4, max_chars: int = 8000) -> str:
    """OCR each image and join the non-empty text. Never raises — any failure (missing
    deps, undecodable image, tesseract error) contributes nothing; oversized images are
    skipped. Output is capped at max_chars."""
    if not images or not ocr_available():
        return ""
    try:
        import io

        import PIL.Image
        import pytesseract
    except Exception:
        return ""
    parts: list[str] = []
    for raw in images[:max_images]:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) > _MAX_IMAGE_BYTES:
            continue
        try:
            with PIL.Image.open(io.BytesIO(raw)) as img:
                text = pytesseract.image_to_string(img)
        except Exception:
            continue
        text = (text or "").strip()
        if text:
            parts.append(text)
    return "\n".join(parts)[:max_chars]


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
                  (the url may also be a bare string)
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
