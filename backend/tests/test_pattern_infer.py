"""Custom-PII patterns inferred from examples, so an admin need not write regex."""

from __future__ import annotations

import re

from app.pattern_infer import infer


def test_fixed_prefix_and_digits():
    r = infer(["ACME-1234", "ACME-5678"])
    assert r["ok"] and r["regex"] == r"\bACME\-\d{4}\b"
    assert re.search(r["regex"], "ref ACME-4242 attached")
    # The prefix is shared by every example, so it is format, not value.
    assert 'the literal "ACME"' in r["explain"] and "4 digits" in r["explain"]


def test_varying_length_becomes_a_range():
    r = infer(["MRN123", "MRN45678"])        # 3 digits and 5 digits
    assert r["ok"] and r["regex"] == r"\bMRN\d{3,5}\b"
    assert re.search(r["regex"], "MRN9012") and not re.search(r["regex"], "MRN12")


def test_counter_example_is_honoured():
    """A pattern that also matches what the admin excluded is refused, not returned with a
    warning: a detector that half works reads as coverage."""
    r = infer(["ID-1234", "ID-5678"], counter_examples=["ID-9999"])
    assert not r["ok"] and r["false_hits"] == ["ID-9999"]
    r2 = infer(["MRN00123456", "MRN00987654"], counter_examples=["SSN00123456"])
    assert r2["ok"] and r2["false_hits"] == []


def test_one_example_is_refused():
    r = infer(["ACME-1234"])
    assert not r["ok"] and "at least two" in r["error"]


def test_mismatched_shapes_are_refused_rather_than_widened():
    r = infer(["ACME-1234", "1234-ACME"])
    assert not r["ok"] and "share a shape" in r["error"]


def test_differing_separators_are_refused():
    r = infer(["ACME-1234", "ACME_1234"])
    assert not r["ok"] and "separators differ" in r["error"]


def test_output_survives_the_engine_s_own_safety_check():
    """The inferred string has to be something custom_pii_patterns will actually load:
    _safe_custom_regex rejects invalid and ReDoS-risky patterns."""
    from app.detectors.patterns import _safe_custom_regex, custom_pii_patterns
    r = infer(["CUST-4821-A", "CUST-9930-B"])
    assert _safe_custom_regex(r["regex"]) is not None
    loaded = custom_pii_patterns(f"Customer ID={r['regex']}")
    assert [lbl for lbl, _ in loaded] == ["Customer ID"]
    assert loaded[0][1].search("order for CUST-1111-Z")


def test_no_anchor_when_the_edge_is_not_alphanumeric():
    r = infer(["#1234", "#5678"])
    assert r["ok"] and r["regex"].startswith("\\#")


def test_oversized_input_is_refused():
    assert not infer(["A1", "A2"] * 20)["ok"]
    assert not infer(["A" * 300, "B" * 300])["ok"]
