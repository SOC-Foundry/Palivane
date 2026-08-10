"""International PII coverage — EU / APAC / Americas national IDs, check-digit validated."""

from __future__ import annotations

from app.detectors import AnalysisInput, ShadowAIDetector, Surface

det = ShadowAIDetector()


def _labels(text: str) -> list[str]:
    item = AnalysisInput(content=text, surface=Surface.AI_USAGE)
    out = []
    for sig in det.analyze(item):
        if sig.category.value == "pii_exposure":
            out.append(sig.detail + " " + sig.evidence)
    return out


def _flags(text: str, needle: str) -> bool:
    return any(needle in d for d in _labels(text))


def test_canada_sin_valid_flagged_invalid_not():
    assert _flags("customer SIN: 046-454-286", "Canada SIN")
    assert not _flags("SIN: 123-456-789", "Canada SIN")   # not Luhn-valid


def test_brazil_cpf():
    assert _flags("CPF 111.444.777-35 on file", "Brazil CPF")
    assert not _flags("id 111.444.777-00", "Brazil CPF")   # bad check digits


def test_netherlands_bsn_requires_context_and_validates():
    assert _flags("BSN 111222333", "Netherlands BSN")
    assert not _flags("order number 111222333", "Netherlands BSN")   # no context word
    assert not _flags("BSN 111222334", "Netherlands BSN")            # fails 11-test


def test_singapore_nric():
    assert _flags("NRIC S1234567D issued", "Singapore NRIC")
    assert not _flags("ref S1234567A", "Singapore NRIC")   # wrong checksum letter


def test_spain_dni_nie():
    assert _flags("DNI 12345678Z", "Spain DNI")
    assert not _flags("code 12345678A", "Spain DNI")        # wrong control letter


def test_mexico_curp_self_identifying():
    # structurally distinctive — flagged without a keyword
    assert _flags("HEGG560427MVZRRL04", "Mexico CURP")


def test_italy_codice_fiscale():
    assert _flags("RSSMRA85T10A562S", "Italy Codice Fiscale")


def test_us_ssn_still_works():
    assert _flags("SSN 123-45-6789", "")   # any pii signal present
    assert _labels("SSN 123-45-6789")


def test_plain_prose_has_no_false_national_ids():
    # a paragraph of ordinary text and a random order number shouldn't trip any locale ID
    txt = ("Thanks for the update — order 12345678 shipped Tuesday and the invoice total "
           "was 4471 for 3 units. Call me at the office if anything's off.")
    labels = " ".join(_labels(txt))
    for n in ("Canada SIN", "Brazil CPF", "Netherlands BSN", "Singapore NRIC",
              "Spain DNI", "Mexico CURP", "Italy Codice"):
        assert n not in labels, (n, labels)
