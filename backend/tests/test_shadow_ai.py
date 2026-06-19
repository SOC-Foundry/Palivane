"""Module C — shadow-AI governance: secrets/PII/IP leaving for unsanctioned tools."""

from __future__ import annotations

from app.detectors.base import AnalysisInput, Category, Surface
from app.detectors.patterns import find_secrets
from app.detectors.shadow_ai import ShadowAIDetector, _luhn_ok

det = ShadowAIDetector()


def _cats(content="", destination=None) -> set[Category]:
    meta = {"destination": destination} if destination else {}
    item = AnalysisInput(content=content, surface=Surface.AI_USAGE, metadata=meta)
    return {s.category for s in det.analyze(item)}


def test_secret_in_outbound_content():
    assert Category.SECRET_LEAK in _cats("here is the prod key AKIAABCDEFGHIJKLMNOP for testing")


def test_ssn_is_pii():
    assert Category.PII_EXPOSURE in _cats("the employee SSN is 123-45-6789")


def test_valid_credit_card_is_pii():
    # 4111 1111 1111 1111 is the canonical Luhn-valid test Visa.
    assert Category.PII_EXPOSURE in _cats("charge card 4111 1111 1111 1111 today")


def test_invalid_card_number_not_flagged():
    # Fails Luhn → should not be reported as a payment card.
    assert Category.PII_EXPOSURE not in _cats("order number 1234 5678 9012 3456 shipped")


def test_contact_list_is_pii():
    assert Category.PII_EXPOSURE in _cats("a@x.com, b@x.com, c@x.com and d@x.com")


def test_single_email_not_flagged():
    assert Category.PII_EXPOSURE not in _cats("reply to me at jane@example.com")


def test_source_code_leak():
    code = "def run(x):\n    import os\n    return os.system(x)"
    assert Category.SOURCE_CODE_LEAK in _cats(code)


def test_confidential_marking():
    assert Category.SOURCE_CODE_LEAK in _cats("This document is CONFIDENTIAL and internal use only.")


def test_known_tool_is_unsanctioned_by_default():
    assert Category.UNSANCTIONED_AI in _cats("hello", destination="https://chat.openai.com/c/123")


def test_sanctioned_tool_not_flagged(monkeypatch):
    from app.detectors import shadow_ai
    monkeypatch.setattr(shadow_ai.settings, "sanctioned_ai_tools", "claude.ai")
    cats = _cats("just a brainstorm question", destination="claude.ai")
    assert Category.UNSANCTIONED_AI not in cats


def test_clean_content_no_destination_is_silent():
    assert _cats("Can you help me write a haiku about spring?") == set()


def test_luhn():
    assert _luhn_ok("4111111111111111")
    assert not _luhn_ok("4111111111111112")


def test_find_secrets_shared_helper():
    assert find_secrets("password = hunter2supersecret")
    assert find_secrets("token sk-ant-abcdefghijklmnopqrstuv")
    assert find_secrets("nothing sensitive here") == []
