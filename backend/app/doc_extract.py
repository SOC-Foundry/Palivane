"""Readable text out of a file, whatever the file is.

A regulated record is more often a PDF, a spreadsheet or a screenshot than a typed
sentence, and a scanner that only reads plain text reports every one of those as clean.
This is the one place that turns bytes into something the detectors can read, so every
surface that handles a file — Slack attachments, S3 objects, Drive/SharePoint documents —
gets the same coverage and the same honest answer about what it could not open.

Three tiers, in order of how much they need:

  text      the bytes already are text (utf-8 decodes)
  document  text lives inside a container: OOXML (docx/xlsx/pptx, which are ZIPs of XML)
            and unencrypted PDFs. Stdlib only, so the at-rest CLI scanners run the exact
            same code — the implementation lives in cli/palivane_detect.py and is loaded
            from there rather than copied, because two copies of a parser drift.
  ocr       an image, via the existing opt-in OCR path (Pillow + pytesseract, local, off
            unless PALIVANE_OCR is set). Never a cloud vision API: shipping a customer's
            screenshot to a third party to find out whether it holds their secrets is the
            exfil path this product exists to remove.

Anything else returns ("", "") and the caller reports it as unread. A scanner that
silently skipped a file is indistinguishable from one that found nothing in it, and only
one of those is safe to act on.
"""

from __future__ import annotations

import importlib.util
import os

_IMAGE_EXTS = ("png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "tif")
_DOC_EXTS = ("pdf", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
             "rtf", "odt", "ods", "odp")   # RTF is text; OpenDocument is a ZIP of XML
# Containers this cannot open. Listed so the caller can say WHY, rather than lumping them
# in with "unknown": pre-2007 Office (.doc/.xls/.ppt) is a binary OLE format that needs a
# parser library, and Apple iWork stores its body as proprietary binary inside the zip.
_KNOWN_UNREADABLE = ("doc", "xls", "ppt", "pages", "numbers", "key")

_detect = None


def _detector():
    """cli/palivane_detect.py, loaded by path — the same module the at-rest scanners run."""
    global _detect
    if _detect is None:
        here = os.path.dirname(os.path.abspath(__file__))
        roots = (os.path.dirname(os.path.dirname(here)), os.path.dirname(here))
        for root in roots:
            path = os.path.join(root, "cli", "palivane_detect.py")
            if os.path.isfile(path):
                spec = importlib.util.spec_from_file_location("palivane_detect", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                _detect = mod
                break
        else:
            _detect = False           # not packaged: documents degrade to unreadable
    return _detect or None


def _ext(name: str) -> str:
    return (name or "").rsplit(".", 1)[-1].lower() if "." in (name or "") else ""


def kind_of(name: str, mimetype: str = "") -> str:
    """What tier this file needs: "text" | "document" | "image" | "" (cannot read)."""
    ext, mime = _ext(name), (mimetype or "").lower()
    if ext in _DOC_EXTS or mime == "application/pdf" or "officedocument" in mime:
        return "document"
    if ext in _IMAGE_EXTS or mime.startswith("image/"):
        return "image"
    if ext in _KNOWN_UNREADABLE:
        return ""
    if mime.startswith("text/") or mime in ("application/json", "application/xml",
                                            "application/x-ndjson", "application/sql"):
        return "text"
    return "text" if not mime and not ext else ("text" if ext else "")


def extract(name: str, data: bytes, mimetype: str = "") -> tuple[str, str]:
    """(text, how) for a file's bytes. `how` is the tier that produced it, or "" when
    nothing could read it — which the caller must surface rather than treat as clean."""
    if not data:
        return "", ""
    kind = kind_of(name, mimetype)
    if kind == "image":
        from .ocr import extract_image_text, ocr_available
        if not ocr_available():
            return "", ""             # OCR off or not installed: unread, not clean
        text = extract_image_text([bytes(data)], max_images=1)
        return (text, "ocr") if text.strip() else ("", "")
    if kind in ("document", "text"):
        det = _detector()
        if det is None:
            return "", ""
        text = det.extract_text(name, bytes(data))
        return (text, kind) if text.strip() else ("", "")
    return "", ""
