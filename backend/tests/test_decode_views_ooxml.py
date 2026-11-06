"""Obfuscation by formatting (security review D5) and Word extraction gaps (D10). Values are
assembled from fragments; the AWS-shaped key is the documented example format."""
from __future__ import annotations

import io
import zipfile

from app.detectors import AnalysisInput, Surface
from app.detectors.decode import decode_obfuscated_detail, literal_views, reshaped_views
from app.detectors.shadow_ai import ShadowAIDetector

KEY = "AKIA" + "IOSFODNN" + "7EXAMPLE"
SSN = "078" + "-05-" + "1120"


def _secret_sigs(content):
    item = AnalysisInput(content=content, subject="", sender="d", channel="t", surface=Surface.AI_USAGE)
    return ShadowAIDetector()._scan_reshaped(item)


def test_escapes_and_entities_are_decoded():
    esc = "".join(f"\\u{ord(c):04x}" for c in f"ssn {SSN}")
    ent = "".join(f"&#{ord(c)};" for c in f"ssn {SSN}")
    assert SSN in decode_obfuscated_detail(esc).text
    assert SSN in decode_obfuscated_detail(ent).text
    assert literal_views("plain text") == []


def test_reshaped_keys_are_found():
    for disguised in ("-".join(KEY), " ".join(KEY), KEY[:10] + "\n" + KEY[10:], KEY[::-1]):
        assert _secret_sigs(f"here: {disguised} ok"), repr(disguised)


def test_plain_prose_reshapes_to_nothing():
    assert _secret_sigs("We met on Tuesday.\nThe plan is a b c d e f g h, then lunch.") == []
    assert reshaped_views("abc")[-1] == "cba"


def _docx(parts: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, b in parts.items():
            z.writestr(n, b)
    return buf.getvalue()


def test_word_runs_join_and_more_parts_are_read():
    from app.doc_extract import extract_detail
    k1, k2 = KEY[:6], KEY[6:]
    doc = (f'<w:document><w:body><w:p><w:r><w:t>{k1}</w:t></w:r><w:r><w:rPr><w:b/></w:rPr>'
           f'<w:t>{k2}</w:t></w:r></w:p></w:body></w:document>')
    data = _docx({"word/document.xml": doc,
                  "word/footer1.xml": "<w:ftr><w:p><w:r><w:t>footer words</w:t></w:r></w:p></w:ftr>",
                  "docProps/core.xml": "<cp:coreProperties><dc:title>title words</dc:title></cp:coreProperties>"})
    text, how, partial = extract_detail("x.docx", data)
    assert KEY in text and "footer words" in text and "title words" in text and not partial


def test_an_embedded_object_marks_the_read_partial():
    from app.doc_extract import extract_detail
    data = _docx({"word/document.xml": "<w:document><w:body><w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>",
                  "word/embeddings/oleObject1.bin": b"\x00\x01"})
    assert extract_detail("x.docx", data).partial
