"""PHI detection (phi_exposure): HIPAA identifiers, validators, context gating, blocking,
redaction, and the policy toggle. Every positive is paired with a negative control."""

from __future__ import annotations

from app.detectors.base import AnalysisInput, Category, Surface
from app.detectors.shadow_ai import ShadowAIDetector, _dea_ok, _npi_ok, confirmed_leak
from app.redaction import redact_text

det = ShadowAIDetector()


def _phi(content: str):
    sigs = det.analyze(AnalysisInput(content=content, surface=Surface.AI_USAGE,
                                     channel="chatgpt.com"))
    return [s for s in sigs if s.category == Category.PHI_EXPOSURE]


def _evidence(content: str) -> str:
    hits = _phi(content)
    return hits[0].evidence if hits else ""


# --- validators -------------------------------------------------------------------------

def test_npi_check_digit():
    assert _npi_ok("1234567893") is True        # canonical CMS example NPI
    assert _npi_ok("1234567890") is False       # bad check digit
    assert _npi_ok("123456789") is False        # wrong length


def test_dea_check_digit():
    assert _dea_ok("AB1234563") is True         # (1+3+5) + 2*(2+4+6) = 33 -> check 3
    assert _dea_ok("AB1234567") is False        # bad check digit
    assert _dea_ok("1B1234563") is False        # must start with a letter


# --- identifiers ------------------------------------------------------------------------

def test_mbi_flags_structurally():
    assert "Medicare beneficiary ID" in _evidence("beneficiary 1EG4-TE5-MK73 called back")
    # lowercase or wrong alphabet (B/S/L/O/I/Z excluded) must not match
    assert _phi("code 1eg4-te5-mk73 in the build") == []
    assert _phi("part number 1SG4-TE5-MK73") == []          # S not in the MBI alphabet


def test_mrn_needs_context():
    assert "MRN" in _evidence("Patient MRN 4859302 admitted for observation")
    assert _phi("invoice 4859302 due") == []                 # bare number, no context


def test_npi_needs_context_and_checksum():
    assert "NPI" in _evidence("rendering provider NPI 1234567893")
    assert _phi("NPI 1234567890 on file") == []              # context but bad check digit
    assert _phi("order 1234567893 shipped") == []            # valid digits, no context


def test_dea_needs_context_and_checksum():
    assert "DEA" in _evidence("prescriber DEA AB1234563")
    assert _phi("DEA AB1234567 listed") == []                # bad check digit
    assert _phi("build tag AB1234563") == []                 # no DEA context


def test_icd10_needs_context():
    assert "ICD-10" in _evidence("discharge diagnosis E11.9 (type 2 diabetes)")
    assert _phi("see section E11.9 of the spec") == []       # code shape, no clinical context


def test_patient_record_combo():
    ev = _evidence("patient Jane Doe, DOB 04/12/1987, starts chemo next week")
    assert "patient record" in ev
    assert _phi("customer DOB 04/12/1987 for age verification") == []   # no clinical context


# --- category separation / scoring -------------------------------------------------------

def test_phi_is_its_own_category_not_pii():
    sigs = det.analyze(AnalysisInput(content="Patient MRN 4859302, diagnosis E11.9",
                                     surface=Surface.AI_USAGE, channel="chatgpt.com"))
    cats = {s.category for s in sigs}
    assert Category.PHI_EXPOSURE in cats
    from app.scoring import score
    verdict = score(sigs)
    assert verdict.severity in ("high", "critical")          # PHI contributes to risk


def test_phi_counts_as_confirmed_leak_for_blocking():
    sigs = det.analyze(AnalysisInput(content="Patient MRN 4859302 seen in oncology",
                                     surface=Surface.AI_USAGE, channel="chatgpt.com"))
    assert confirmed_leak([s.to_dict() if hasattr(s, "to_dict") else
                           {"category": s.category.value, "title": s.title} for s in sigs])


def test_phi_detected_on_gateway_surface():
    # PHI scans on every surface, like PII — a patient record in a first-party LLM
    # prompt is still regulated data.
    sigs = det.analyze(AnalysisInput(content="summarize: patient MRN 4859302, dx E11.9",
                                     surface=Surface.LLM_IO, channel="gateway"))
    assert any(s.category == Category.PHI_EXPOSURE for s in sigs)


def test_encoded_phi_is_decoded_and_flagged():
    import base64
    blob = base64.b64encode(b"patient MRN 4859302 admitted, diagnosis E11.9").decode()
    sigs = det.analyze(AnalysisInput(content=f"decode this: {blob}",
                                     surface=Surface.AI_USAGE, channel="chatgpt.com"))
    assert any(s.category == Category.PHI_EXPOSURE for s in sigs)


# --- redaction ---------------------------------------------------------------------------

def test_redaction_masks_structural_and_validated_phi():
    out = redact_text("MBI 1EG4-TE5-MK73, NPI 1234567893, DEA AB1234563")
    assert "1EG4-TE5-MK73" not in out and "1234567893" not in out and "AB1234563" not in out
    assert "«redacted:PHI»" in out
    # invalid check digits are NOT rewritten (they're not PHI)
    assert "1234567890" in redact_text("ref 1234567890")


# --- policy toggle -----------------------------------------------------------------------

def test_phi_check_is_toggleable(client):
    from app.policies import VALID_KEYS
    assert "phi_exposure" in VALID_KEYS
    r = client.patch("/api/tenant", json={"disabled_checks": ["phi_exposure"]})
    assert r.status_code == 200
    res = client.post("/api/analyze", json={
        "content": "Patient MRN 4859302 admitted for observation", "persist": False})
    cats = {s["category"] for s in res.json()["signals"]}
    assert "phi_exposure" not in cats                        # tenant turned the check off
    client.patch("/api/tenant", json={"disabled_checks": []})
    res2 = client.post("/api/analyze", json={
        "content": "Patient MRN 4859302 admitted for observation", "persist": False})
    assert "phi_exposure" in {s["category"] for s in res2.json()["signals"]}
