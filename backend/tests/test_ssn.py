"""SSN detection: dashed (block), unformatted 9-digit (warn), context-boosted, structure-gated."""

from __future__ import annotations

from app.detectors.shadow_ai import ShadowAIDetector, _valid_ssn9
from app.detectors.base import AnalysisInput, Category, Surface

_d = ShadowAIDetector()


def _pii_weight(content):
    sigs = [s for s in _d.analyze(AnalysisInput(content=content, surface=Surface.AI_USAGE))
            if s.category == Category.PII_EXPOSURE]
    return sigs[0].weight if sigs else None


def test_dashed_ssn_blocks():
    assert _pii_weight("my ssn is 123-45-6789") == 0.8
    assert _pii_weight("123 45 6789") == 0.8          # spaced form too


def test_unformatted_ssn_warns():
    w = _pii_weight("please clean up this record: 123456789")
    assert w == 0.55                                   # warn-level (no context)


def test_unformatted_ssn_with_context_blocks():
    assert _pii_weight("SSN 123456789") == 0.8
    assert _pii_weight("social security 123456789") == 0.8


def test_structure_gating_rejects_non_ssn():
    # 9-digit runs that can't be SSNs are not flagged as PII.
    assert _pii_weight("order id 000000000") is None   # area 000
    assert _pii_weight("ref 999999999") is None        # 900-999 area
    assert _pii_weight("code 123006789") is None        # group 00


def test_valid_ssn9():
    assert _valid_ssn9("123456789")
    assert not _valid_ssn9("000112222") and not _valid_ssn9("666112222")
    assert not _valid_ssn9("900112222") and not _valid_ssn9("123002222")


def test_ingest_warns_on_unformatted_ssn(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ssn", "actor": "u@acme.com"}).json()["token"]
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "here is the number 123456789", "destination": "https://claude.ai/"},
                        headers={"X-Palivane-Token": key}).json()
    assert r["action"] == "warn"
    assert "pii_exposure" in {s["category"] for s in r["signals"]}


def test_nine_digits_labeled_as_another_id_are_not_guessed_ssns():
    # A numeric GitHub user id in a WIF condition was blocked as "possible SSN (9-digit)".
    for text in ("assertion.actor_id=='234567890'",
                 "your numeric GitHub user ID (234567890, for octocat)",
                 "GCP project number 234567890 owns the pool",
                 "order #234567890 shipped", "gh api repos/acme/app -q .id  # prints 234567890"):
        assert _pii_weight(text) is None, text


def test_unlabeled_or_ssn_cued_nine_digits_still_count():
    assert _pii_weight("the number is 234567890") == 0.55
    assert _pii_weight("customer record: Jane Doe, 234567890") == 0.55   # a person, not an id
    assert _pii_weight("account holder Jane Doe, 234567890") == 0.55     # label too far back
    assert _pii_weight("user id 345678901, ssn 234567890") == 0.8         # the SSN cue wins
    # one labeled id doesn't excuse a second, unlabeled run
    assert _pii_weight("order 345678901\n\nJane Doe 234567890") == 0.55
