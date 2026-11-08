"""Detection hardening (security review D2–D4). Payloads are assembled from fragments.

D2  a media magic in front of text is not media: it reaches the detectors; a real
    document container's text is kept when the blob is stripped.
D3  decoding is budgeted by bytes, not blob count; nested and compressed encodings decode;
    an exhausted budget marks the scan partial.
D4  one canonical Unicode fold: soft hyphens, combining marks, zero-width characters and
    non-ASCII digits don't split a match, in the PII pass too."""
from __future__ import annotations

import base64
import gzip
import os
import zlib

from app.detectors import AnalysisInput, Surface
from app.detectors.decode import decode_obfuscated_detail
from app.detectors.normalize import canonical_fold
from app.detectors.patterns import ATTACHMENT_PLACEHOLDER, strip_media_blobs
from app.detectors.shadow_ai import ShadowAIDetector

SSN = "078" + "-15-" + "1120"
b64 = lambda b: base64.b64encode(b).decode()          # noqa: E731


def _pii_labels(text: str) -> str:
    return " ".join(s.evidence or "" for s in ShadowAIDetector()._scan_pii(text))


def _item(content: str) -> AnalysisInput:
    return AnalysisInput(content=content, subject="", sender="dev", channel="test",
                         surface=Surface.AI_USAGE)


# --- D2 -------------------------------------------------------------------------------

def test_fake_media_header_in_front_of_text_is_not_stripped():
    blob = b64(b"%PDF-" + f"record: ssn {SSN} ".encode() * 10)
    out = strip_media_blobs(f"see {blob}")
    assert ATTACHMENT_PLACEHOLDER not in out
    assert SSN in decode_obfuscated_detail(out).text


def test_real_binary_media_is_still_stripped():
    blob = b64(b"\xff\xd8\xff\xe0" + os.urandom(600))
    assert strip_media_blobs(f"img {blob} end") == f"img {ATTACHMENT_PLACEHOLDER} end"


def test_real_pdf_container_text_is_kept():
    words = b"BT /F1 12 Tf (quarterly container words) Tj ET"
    stream = zlib.compress(words) + os.urandom(200)    # binary body, like a real PDF
    pdf = (b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Length " + str(len(stream)).encode()
           + b" /Filter /FlateDecode >>\nstream\n" + stream + b"\nendstream\nendobj\n%%EOF\n")
    out = strip_media_blobs(b64(pdf))
    assert out.startswith(ATTACHMENT_PLACEHOLDER)
    assert "quarterly container words" in out


# --- D3 -------------------------------------------------------------------------------

def test_decoy_blobs_ahead_of_the_payload_dont_hide_it():
    decoys = " ".join(b64(f"benign filler number {i} ok".encode()) for i in range(60))
    got = decode_obfuscated_detail(decoys + " " + b64(f"ssn {SSN}".encode()))
    assert SSN in got.text and not got.exhausted


def test_payload_past_the_old_per_blob_cap_is_decoded():
    got = decode_obfuscated_detail(b64(("lorem ipsum " * 600 + f"ssn {SSN}").encode()))
    assert SSN in got.text


def test_nested_and_compressed_encodings_decode():
    inner = f"ssn {SSN} on file".encode()
    assert SSN in decode_obfuscated_detail(b64(b64(inner).encode())).text
    assert SSN in decode_obfuscated_detail(b64(gzip.compress(inner))).text
    assert SSN in decode_obfuscated_detail(zlib.compress(inner).hex()).text


def test_exhausted_budget_marks_the_scan_partial(monkeypatch):
    import app.detectors.decode as d
    monkeypatch.setattr(d, "_BUDGET", 64)
    d._decode_blobs.cache_clear()
    text = " ".join(b64(f"filler text block {i} here".encode()) for i in range(10))
    assert decode_obfuscated_detail(text).exhausted
    sigs = ShadowAIDetector()._scan_encoded(_item(text))
    assert any((s.evidence or "") == "encoded=over budget" for s in sigs)
    d._decode_blobs.cache_clear()


# --- D4 -------------------------------------------------------------------------------

def test_canonical_fold():
    assert canonical_fold("07­8") == "078"                       # soft hyphen
    assert canonical_fold("0̲7̲8") == "078"                 # combining low line
    assert canonical_fold("٠٧٨") == "078"              # Arabic-Indic digits
    assert canonical_fold("０７８") == "078"              # fullwidth
    assert canonical_fold("café 한국") == "cafe 한국"   # Hangul survives
    assert canonical_fold("plain ascii") == "plain ascii"


def test_pii_pass_sees_through_unicode_splitting():
    for disguised in (
        SSN[:3] + "​" + SSN[3:],                                     # zero-width
        SSN[:2] + "­" + SSN[2:],                                     # soft hyphen
        "".join(c + "̲" if c.isdigit() else c for c in SSN),         # combining marks
        SSN.translate(str.maketrans("0123456789", "٠١٢٣٤"
                                                  "٥٦٧٨٩")),
    ):
        assert "SSN" in _pii_labels(f"employee ssn {disguised}"), repr(disguised)
