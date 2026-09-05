"""Document text extraction: the tier that turns a PDF, a spreadsheet or a screenshot into
something the detectors can read.

The failure that matters here is a FALSE CLEAN — reporting that a file was scanned when
nothing actually read it. Most of these tests are about the extractor admitting it could
not open something, rather than about it succeeding.
"""

from __future__ import annotations

import importlib.util
import io
import pathlib
import zipfile
import zlib

from app.doc_extract import extract, kind_of

_MODULE = pathlib.Path(__file__).resolve().parents[2] / "cli" / "palivane_detect.py"
_spec = importlib.util.spec_from_file_location("palivane_detect", _MODULE)
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)

AWS = "AKIAIOSFODNN7EXAMPLE"
SSN = "412-88-7390"


def _docx(*paragraphs: str) -> bytes:
    buf = io.BytesIO()
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml",
                   f'<?xml version="1.0"?><w:document xmlns:w="x"><w:body>{body}</w:body></w:document>')
    return buf.getvalue()


def _xlsx(*cells: str) -> bytes:
    buf = io.BytesIO()
    si = "".join(f"<si><t>{c}</t></si>" for c in cells)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/sharedStrings.xml", f"<sst>{si}</sst>")
    return buf.getvalue()


def _pptx(*slides: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, text in enumerate(slides, 1):
            z.writestr(f"ppt/slides/slide{i}.xml", f"<p:sld><a:p><a:t>{text}</a:t></a:p></p:sld>")
    return buf.getvalue()


def _pdf(text: str, compress: bool = True) -> bytes:
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    body = zlib.compress(content) if compress else content
    return (b"%PDF-1.4\n1 0 obj<</Length " + str(len(body)).encode() + b">>stream\n"
            + body + b"\nendstream\nendobj\ntrailer<<>>\n%%EOF")


# --- the formats that were previously invisible --------------------------------------------

def test_docx_secret_is_found():
    text, how = extract("spec.docx", _docx(f"deploy key {AWS}", "nothing else"))
    assert how == "document"
    assert any(c == "secret_leak" for c, _, _, _ in d.scan_all(text))


def test_xlsx_pii_is_found():
    """An exported spreadsheet is the single most common shape of a bulk PII leak."""
    text, _ = extract("export.xlsx", _xlsx("name", "ssn", "Jane Roe", SSN))
    assert any(c == "pii_exposure" for c, _, _, _ in d.scan_all(text))


def test_pptx_is_read():
    text, _ = extract("deck.pptx", _pptx("Q3 plan", f"creds {AWS}"))
    assert AWS in text


def test_pdf_compressed_and_uncompressed():
    for compress in (True, False):
        text, how = extract("report.pdf", _pdf(f"aws key {AWS}", compress))
        assert how == "document" and AWS in text, f"compress={compress}"


def test_pdf_detected_by_magic_bytes_without_an_extension():
    text, _ = extract("noextension", _pdf(f"key {AWS}"))
    assert AWS in text


def test_spreadsheet_rows_do_not_run_together():
    """Cells joined without separators would let one row's digits form a match with the
    next one's — a false positive that is hard to explain to a customer."""
    text, _ = extract("x.xlsx", _xlsx("111", "222"))
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    assert lines == ["111", "222"], f"cells must not share a line: {text!r}"


# --- admitting defeat, which matters more --------------------------------------------------

def test_legacy_office_is_reported_unreadable_not_clean():
    assert kind_of("old.doc") == ""
    assert extract("old.doc", b"\xd0\xcf\x11\xe0legacy OLE") == ("", "")


def test_an_undecodable_pdf_yields_nothing_rather_than_mojibake():
    """A CID-encoded or encrypted PDF must not produce garbage: garbage text means garbage
    findings, and an analyst chasing a hallucinated secret is worse than a missed file."""
    junk = b"%PDF-1.4\nstream\n" + bytes(range(256)) * 4 + b"\nendstream"
    assert extract("enc.pdf", junk) == ("", "")


def test_a_corrupt_zip_does_not_raise():
    assert extract("broken.docx", b"PK\x03\x04not really a zip") == ("", "")


def test_empty_input():
    assert extract("a.pdf", b"") == ("", "")


def test_image_without_ocr_is_unreadable_not_clean(monkeypatch):
    """The format most likely to carry a pasted credential must never come back 'scanned'
    when nothing looked at it."""
    import app.ocr as ocr
    monkeypatch.setattr(ocr, "ocr_available", lambda: False)
    assert kind_of("shot.png") == "image"
    assert extract("shot.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64) == ("", "")


def test_image_goes_through_ocr_when_available(monkeypatch):
    import app.ocr as ocr
    monkeypatch.setattr(ocr, "ocr_available", lambda: True)
    monkeypatch.setattr(ocr, "extract_image_text", lambda imgs, max_images=4, **k: f"key {AWS}")
    text, how = extract("shot.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    assert how == "ocr" and AWS in text


def test_ocr_never_reaches_a_cloud_service():
    """Shipping a customer's screenshot to a vision API to find out whether it holds their
    secrets is the exact exfil path this product exists to remove."""
    src = (pathlib.Path(__file__).resolve().parents[1] / "app" / "ocr.py").read_text()
    for forbidden in ("http://", "https://", "requests", "urllib", "boto3", "vision"):
        assert forbidden not in src, f"ocr.py must stay local, found {forbidden!r}"


def test_plain_text_still_passes_straight_through():
    text, how = extract("notes.txt", b"ssn " + SSN.encode())
    assert how == "text" and SSN in text


def test_the_server_and_the_cli_scanners_share_one_implementation():
    """Two copies of a parser drift, and the at-rest scanners must agree with the backend
    about what a file contains."""
    same = d.extract_text("a.docx", _docx(f"key {AWS}"))
    server, _ = extract("a.docx", _docx(f"key {AWS}"))
    assert same == server and AWS in server


def test_pdf_whose_deflate_payload_ends_in_a_newline():
    """A PDF stream is followed by an EOL before "endstream", and the deflate payload can
    itself END in 0x0a or 0x0d. Stripping those to remove the delimiter truncates the
    stream and the file extracts to nothing — silently, so the scan reports it clean.

    This exact string is the one that caught it: zlib.compress() of it ends in 0x0a."""
    payload = f"BT /F1 12 Tf 72 720 Td (customer export - aws key {AWS}) Tj ET"
    comp = zlib.compress(payload.encode())
    assert comp[-1:] == b"\n", "the fixture must still exercise the case it was written for"
    pdf = (b"%PDF-1.4\n1 0 obj<</Length " + str(len(comp)).encode()
           + b"/Filter/FlateDecode>>stream\n" + comp
           + b"\nendstream\nendobj\ntrailer<<>>\n%%EOF")
    text, how = extract("export.pdf", pdf)
    assert how == "document" and AWS in text


# --- newly readable: RTF (text format) + OpenDocument (zip of XML) --------------------------

def _odf(*paragraphs: str) -> bytes:
    buf = io.BytesIO()
    body = "".join(f"<text:p>{p}</text:p>" for p in paragraphs)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        z.writestr("content.xml",
                   '<?xml version="1.0"?><office:document-content xmlns:office="a" '
                   f'xmlns:text="b"><office:body><office:text>{body}'
                   "</office:text></office:body></office:document-content>")
    return buf.getvalue()


def _rtf(*paragraphs: str) -> bytes:
    body = r"\par ".join(paragraphs)
    return (r"{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}\f0\fs24 " + body + "}").encode("latin-1")


def test_rtf_is_now_readable_and_scanned():
    assert kind_of("leak.rtf") == "document"
    text, how = extract("leak.rtf", _rtf(f"prod key {AWS}", f"customer SSN {SSN}"))
    assert how == "document"
    cats = {c for c, _, _, _ in d.scan_all(text)}
    assert "secret_leak" in cats and "pii_exposure" in cats


def test_odt_is_now_readable_and_scanned():
    assert kind_of("notes.odt") == "document"
    text, how = extract("notes.odt", _odf("Confidential board pack", f"SSN {SSN}"))
    assert how == "document" and SSN in text


def test_ods_spreadsheet_readable():
    assert kind_of("book.ods") == "document"
    text, _ = extract("book.ods", _odf("name", "ssn", f"Jane Roe {SSN}"))
    assert SSN in text


def test_legacy_binary_office_still_unreadable():
    # .doc/.xls/.ppt (OLE2 binary) and iWork stay unread — honest, they need real deps.
    for ext in ("doc", "xls", "ppt", "pages", "numbers"):
        assert kind_of(f"x.{ext}") == "", ext
