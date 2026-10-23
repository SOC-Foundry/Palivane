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
import random
import zipfile
import zlib

from app.doc_extract import extract, extract_detail, kind_of

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
    monkeypatch.setattr("app.config.settings.gateway_ocr", True)   # PALIVANE_OCR=true
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


# --- SEC-03: what a read skipped -----------------------------------------------------------

def _refs(s: str) -> str:
    """Every character as a numeric reference, alternating decimal, lower and upper hex."""
    forms = (lambda c: f"&#{c};", lambda c: f"&#x{c:x};", lambda c: f"&#X{c:X};")
    return "".join(forms[i % 3](ord(ch)) for i, ch in enumerate(s))


def test_ooxml_numeric_and_hex_references_are_decoded():
    """OOXML writes characters as `&#65;` / `&#x41;`. A detector run on the reference
    instead of the character finds nothing, so the secret must come out as characters."""
    text, how = extract("refs.docx", _docx(f"deploy key {_refs(AWS)}", "a&#xA;b&#xa;c"))
    assert how == "document" and AWS in text
    assert any(c == "secret_leak" for c, _, _, _ in d.scan_all(text))
    assert "a\nb\nc" in text
    text, _ = extract("refs.xlsx", _xlsx("ssn", _refs(SSN)))
    assert any(c == "pii_exposure" for c, _, _, _ in d.scan_all(text))


def test_xml_references_decode_once_and_leave_other_ampersands():
    """One pass: `&amp;lt;` is the text `&lt;`, not `<`. HTML-only names are not XML."""
    assert d._xml_text(b"<t>&amp;lt; AT&amp;T &copy &bogus; &#0; &#xD800;</t>").split() == \
        ["&lt;", "AT&T", "&copy", "&bogus;", "�", "�"]


def test_nested_rtf_destination_does_not_leak_into_the_body():
    """`{\\*\\dest {nested} tail}` is one group. The old lazy regex stopped at the nested
    brace and scanned `tail` as body text."""
    rtf = (r"{\rtf1\ansi{\fonttbl{\f0 Arial;}}"
           r"{\*\datastore {\*\inner 0105} AKIAQWERTYUIOPASDFGH {\x more}}"
           r"\f0 body text \{kept\}\par visible line}").encode("latin-1")
    text, how = extract("nested.rtf", rtf)
    assert how == "document"
    assert "AKIAQWERTYUIOPASDFGH" not in text and "0105" not in text and "more" not in text
    assert "body text kept" in text and "visible line" in text


def _pdf_streams(*streams: tuple[bytes, bytes]) -> bytes:
    """A PDF whose content streams are (dictionary entries, raw body) pairs."""
    out = b"%PDF-1.4\n"
    for i, (dict_extra, body) in enumerate(streams, 1):
        out += (f"{i} 0 obj<</Length {len(body)}".encode() + dict_extra + b">>stream\n"
                + body + b"\nendstream\nendobj\n")
    return out + b"trailer<<>>\n%%EOF"


def test_pdf_hex_strings_and_quote_operators_are_read():
    hex_aws = AWS.encode().hex().upper()
    content = (f"BT /F1 12 Tf 72 720 Td <{hex_aws}> Tj ET\n"
               f"BT 14 TL (next line {SSN}) ' 1 0 (spaced line) \" ET\n"
               "BT [(arr) -20 <61 72 72 6179>] TJ ET").encode()
    for extra, body in ((b"", content),
                        (b"/Filter/FlateDecode", zlib.compress(content))):
        text, how, partial = extract_detail("hex.pdf", _pdf_streams((extra, body)))
        assert how == "document" and not partial
        assert AWS in text and SSN in text and "spaced line" in text and "arrarray" in text


def test_a_stream_that_only_uses_the_quote_operator_is_read():
    """No Tj / TJ anywhere: the old gate skipped the whole stream."""
    body = f"BT 14 TL (key {AWS}) ' ET".encode()
    text, _, _ = extract_detail("q.pdf", _pdf_streams((b"/Filter/FlateDecode",
                                                       zlib.compress(body))))
    assert AWS in text


def test_pdf_with_one_corrupt_stream_is_partial_not_whole():
    """One stream inflates, one declared Flate does not. The text that was read is
    returned and scanned, and the read is reported as partial, not as the whole file."""
    good = zlib.compress(f"BT (customer {SSN}) Tj ET".encode())
    bad = b"\x78\x9c" + bytes(range(7, 200))
    pdf = _pdf_streams((b"/Filter/FlateDecode", good), (b"/Filter/FlateDecode", bad))
    text, how, partial = extract_detail("mixed.pdf", pdf)
    assert how == "document" and SSN in text and partial is True
    assert extract("mixed.pdf", pdf) == (text, how)       # extract() keeps its shape
    # Each failure the extractor can name is partial too: an unimplemented filter, a
    # deflate stream cut short, and hex glyph ids it cannot map to text.
    for extra, body in ((b"/Filter/LZWDecode", b"\x80\x0b\x60\x50"),
                        (b"/Filter/FlateDecode",
                         zlib.compress(b"BT (x) Tj ET " + random.Random(1).randbytes(2000))[:200]),
                        (b"", b"BT <00410042> Tj ET")):
        _, _, p = extract_detail("m.pdf", _pdf_streams((b"/Filter/FlateDecode", good),
                                                       (extra, body)))
        assert p is True, extra


def test_pdf_images_and_fonts_do_not_make_a_read_partial():
    good = zlib.compress(f"BT (customer {SSN}) Tj ET".encode())
    pdf = _pdf_streams((b"/Filter/FlateDecode", good),
                       (b"/Subtype/Image/Filter/DCTDecode", b"\xff\xd8\xff\xe0 jpeg"),
                       (b"/Length1 999/Filter/FlateDecode", b"not deflate at all"))
    text, _, partial = extract_detail("clean.pdf", pdf)
    assert SSN in text and partial is False


def test_whole_reads_are_not_partial():
    for name, data in (("a.docx", _docx("x")), ("a.pdf", _pdf("hello")),
                       ("a.rtf", _rtf("hi")), ("a.odt", _odf("hi")), ("a.txt", b"hi")):
        assert extract_detail(name, data).partial is False, name


def test_pdf_words_do_not_run_together():
    """Words joined into one long token read as a high-entropy secret. A wide TJ gap is a
    space, a new line is a line break, and two shows with nothing between stay one word."""
    content = (b"BT /F1 10 Tf 72 720 Td [(Quarterly)-333(export)-12(ed)] TJ\n"
               b"0 -12 Td (second) Tj (line) Tj T* (third line) Tj\n"
               b"1 0 0 1 72 600 Tm (moved) Tj 40 0 Td (along) Tj ET\n"
               b"BT (block) Tj ET BT (two) Tj ET")
    text, _, _ = extract_detail("w.pdf", _pdf_streams((b"/Filter/FlateDecode",
                                                       zlib.compress(content))))
    assert text.split("\n")[:2] == ["Quarterly exported", "secondline"]
    assert "third line moved along block two" in text


def test_pdf_cid_glyph_ids_are_not_emitted_as_text():
    content = b"BT [<00360037>-250<00380039>] TJ (plain words) Tj ET"
    text, _, partial = extract_detail("cid.pdf", _pdf_streams((b"", content)))
    assert text.strip() == "plain words" and partial is True


def test_pdf_decompression_bomb_stops_at_the_cap():
    """A few KB of deflate that inflates past the per-stream cap is read up to the cap and
    reported partial, like an OOXML member past its cap — never inflated whole."""
    bomb = zlib.compress(f"BT (key {AWS}) Tj ET ".encode() + b" " * (3 * d._MAX_PDF_STREAM_BYTES))
    assert len(bomb) < 20_000
    text, _, partial = extract_detail("bomb.pdf", _pdf_streams((b"/Filter/FlateDecode", bomb)))
    assert AWS in text and partial is True
    cap = d._MAX_PDF_STREAM_BYTES
    for head, raw in ((b"/Filter/FlateDecode", bomb), (b"", bomb),
                      (b"/Filter/ASCII85Decode", b"z" * (cap + 10) + b"~>"),
                      (b"/Filter/ASCIIHexDecode", b"41" * (cap + 10) + b">"),
                      (b"/Filter[/ASCIIHexDecode/FlateDecode]", bomb.hex().encode() + b">")):
        body, skipped = d._pdf_stream(head, raw, cap)
        assert len(body) <= cap and skipped is True, head


def test_pdf_document_total_cap_is_partial(monkeypatch):
    monkeypatch.setattr(d, "_MAX_PDF_TOTAL_BYTES", 40)
    s = zlib.compress(f"BT (customer {SSN}) Tj ET".encode())
    text, partial = d.extract_text_detail("t.pdf", _pdf_streams(*[(b"/Filter/FlateDecode", s)] * 3))
    assert SSN in text and partial is True


def test_a_capped_zip_member_is_partial(monkeypatch):
    monkeypatch.setattr(d, "_MAX_ZIP_MEMBER_BYTES", 64)
    assert d.extract_text_detail("big.docx", _docx("x" * 200))[1] is True
    monkeypatch.undo()
    assert d.extract_text_detail("small.docx", _docx("x"))[1] is False
