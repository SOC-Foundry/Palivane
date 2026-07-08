"""Module C — shadow-AI governance: secrets/PII/IP leaving for unsanctioned tools."""

from __future__ import annotations

from app.detectors.base import AnalysisInput, Category, Surface
from app.detectors.patterns import find_high_entropy_tokens, find_secrets
from app.detectors.shadow_ai import ShadowAIDetector, _luhn_ok

det = ShadowAIDetector()


def _cats(content="", destination=None, channel="ai_tool") -> set[Category]:
    meta = {"destination": destination} if destination else {}
    item = AnalysisInput(content=content, surface=Surface.AI_USAGE, channel=channel, metadata=meta)
    return {s.category for s in det.analyze(item)}


def _titles(content="", channel="ai_tool") -> set[str]:
    item = AnalysisInput(content=content, surface=Surface.AI_USAGE, channel=channel)
    return {s.title for s in det.analyze(item)}


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


def test_secrets_detected_with_normal_separators():
    assert "GitHub token" in find_secrets("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "GitLab PAT" in find_secrets("glpat-ABCDEFGHIJKLMNOPQRST")
    assert "npm token" in find_secrets("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    assert "Stripe secret key" in find_secrets("sk_live_ABCDEFGHIJKLMNOP")


def test_secrets_detected_when_separator_stripped():
    # De-dashed / de-underscored to dodge DLP — still caught (distinctive prefix + length).
    assert "GitHub token" in find_secrets("ghpABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "GitHub fine-grained PAT" in find_secrets("github_patABCDEFGHIJKLMNOPQRSTUVWX")
    assert "GitLab PAT" in find_secrets("glpatABCDEFGHIJKLMNOPQRST")
    assert "Anthropic API key" in find_secrets("skantabcdefghijklmnopqrstuv")
    assert "npm token" in find_secrets("npmABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    assert "PyPI token" in find_secrets("pypiABCDEFGHIJKLMNOP")
    assert "Stripe secret key" in find_secrets("skliveABCDEFGHIJKLMNOP")


def test_optional_separator_does_not_flag_prose():
    # The de-dashed patterns must not fire on ordinary words/code sharing a short prefix.
    for benign in ("please skip the standup and ghost the meeting",
                   "run npm install express and start the app",
                   "the ghostwriter published a skateboarding blog",
                   "pypi and glpat are package registries we discussed"):
        assert find_secrets(benign) == [], benign


def test_custom_secret_patterns_from_env(monkeypatch):
    monkeypatch.setenv("CUSTOM_SECRET_PATTERNS", "Acme token=ACME-[0-9A-Z]{8}")
    assert "Acme token" in find_secrets("here is ACME-AB12CD34 in the config")
    assert find_secrets("here is acme-lowercase-nope") == []


def test_invalid_custom_pattern_is_skipped(monkeypatch):
    # A broken regex must not crash detection — the line is ignored.
    monkeypatch.setenv("CUSTOM_SECRET_PATTERNS", "Bad=([unclosed\nGood=ZZ-[0-9]{4}")
    assert find_secrets("code ZZ-1234 here") == ["Good"]


# --- Tier 1: expanded known-prefix secret formats ------------------------------------

def test_tier1_additional_secret_prefixes():
    assert find_secrets("github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789abcd")
    assert find_secrets("glpat-AbCdEf0123456789XyZw")
    assert find_secrets("key sk_live_51HxYzAbCdEfGhIjKlMnOpQr0123")
    assert find_secrets("ya29.AbCdEf0123456789_GhIjKlMnOpQrStUv")
    assert find_secrets("npm_abcdefghijklmnopqrstuvwxyz0123456789")
    assert find_secrets("pypi-AgEIcHlwaS5vcmcCJ0123456789abcdef")
    rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert find_secrets(rsa)


# --- Tier 2: generic high-entropy token heuristic ------------------------------------

def test_tier2_flags_unknown_high_entropy_token():
    assert find_high_entropy_tokens("x7Qm2Lp9Zt4Wd8Rk1Vn6Bc3Hs5Yj0FgAa2Bb")


def test_tier2_ignores_hashes_uuids_and_prose():
    assert find_high_entropy_tokens("commit 9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c") == []  # git SHA
    assert find_high_entropy_tokens("id 550e8400-e29b-41d4-a716-446655440000") == []          # UUID
    assert find_high_entropy_tokens("please summarize the quarterly earnings report") == []
    assert find_high_entropy_tokens("supercalifragilisticexpialidociouswordlong") == []        # single class


def test_tier2_is_warn_level_not_definite_secret_title():
    # An unknown token surfaces as a "possible secret", distinct from a confirmed one.
    titles = _titles("x7Qm2Lp9Zt4Wd8Rk1Vn6Bc3Hs5Yj0FgAa2Bb")
    assert any("Possible secret" in t for t in titles)


def test_tier2_suppressed_for_coding_tools_but_tier1_still_caught():
    token = "x7Qm2Lp9Zt4Wd8Rk1Vn6Bc3Hs5Yj0FgAa2Bb"
    # Coding assistants stream high-entropy code/hashes — heuristic is suppressed.
    assert Category.SECRET_LEAK not in _cats(token, channel="claude-code")
    assert Category.SECRET_LEAK not in _cats(token, channel="cursor")
    # ...but a known-prefix secret is still caught even through a coding tool.
    assert Category.SECRET_LEAK in _cats("AKIAIOSFODNN7EXAMPLE", channel="claude-code")
