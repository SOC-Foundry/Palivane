"""Vendor-documentation sample values are not leaks (2026-11-08 prod review): AWS's sample
key pair and the SSNs the SSA voided after they were published. One character off, they flag.
Values are assembled from fragments so no complete sample sits in the source.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from app.detectors import AnalysisInput, Surface
from app.detectors.patterns import find_secrets
from app.detectors.shadow_ai import ShadowAIDetector

_PATH = Path(__file__).resolve().parents[2] / "cli" / "palivane_detect.py"
_spec = importlib.util.spec_from_file_location("palivane_detect_docsamples", _PATH)
detect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect)

E = "EX" + "AMPLE"
AWS_ID = "AK" + "IA" + "IOSFODNN7" + E
AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCY" + E + "KEY"
SAMPLE_SSNS = ["078" + "-05-" + "1120", "219" + "-09-" + "9999", "457" + "-55-" + "5462"]


def _pii(text):
    item = AnalysisInput(content=text, surface=Surface.AI_USAGE)
    return [s for s in ShadowAIDetector().analyze(item) if s.category.value == "pii_exposure"]


def test_aws_doc_sample_keys_are_not_secrets():
    text = f"aws_access_key_id = {AWS_ID}\naws_secret_access_key = {AWS_SECRET}\n"
    assert not [l for l in find_secrets(text) if "AWS" in l]
    assert not [l for l, _n, _m in detect.scan_text(text) if "AWS" in l]


def test_one_character_off_the_sample_still_flags():
    text = "aws_access_key_id = " + AWS_ID.replace(E, "Q" + E[1:])
    assert [l for l in find_secrets(text) if "AWS" in l]
    assert [l for l, _n, _m in detect.scan_text(text) if "AWS" in l]


def test_published_sample_ssns_are_not_personal_data():
    for ssn in SAMPLE_SSNS:
        assert not _pii(f"my ssn is {ssn}"), ssn
        assert not detect.scan_pii(f"my ssn is {ssn}"), ssn


def test_a_neighbouring_ssn_still_flags():
    ssn = "078" + "-15-" + "1120"
    assert _pii(f"my ssn is {ssn}")
    assert detect.scan_pii(f"my ssn is {ssn}")
