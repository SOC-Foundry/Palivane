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
    # Bulk-email PII counts *personal* mailboxes (freemail providers) only.
    assert Category.PII_EXPOSURE in _cats(
        "a@gmail.com, b@yahoo.co.uk, c@hotmail.com and d@icloud.com")


def test_contact_list_is_warn_tier_not_confirmed_leak():
    # A freemail contact list is heuristic-tier (like the high-entropy token): it warns
    # and records but must NOT trip confirmed_leak()'s monitor-mode hard-block.
    from app.detectors.shadow_ai import CONTACT_LIST_TITLE, confirmed_leak
    item = AnalysisInput(content="a@gmail.com, b@yahoo.com, c@hotmail.com",
                         surface=Surface.AI_USAGE, channel="ai_tool")
    signals = det.analyze(item)
    assert CONTACT_LIST_TITLE in {s.title for s in signals}
    assert confirmed_leak(signals) is False
    # …whereas a known-format PII hit (SSN) stays a confirmed leak.
    ssn = det.analyze(AnalysisInput(content="employee SSN is 123-45-6789",
                                    surface=Surface.AI_USAGE, channel="ai_tool"))
    assert confirmed_leak(ssn) is True


def test_corporate_contact_list_not_flagged():
    # 3+ work addresses are everyday dev content (git logs, CODEOWNERS, on-call
    # rosters) — workflow, not a personal-data leak.
    assert Category.PII_EXPOSURE not in _cats(
        "reviewers: a@acme.com, b@acme.com, c@acme.com and d@partner.io")


def test_mixed_contact_list_counts_only_personal():
    # Two personal + two corporate = below the 3-personal threshold.
    assert Category.PII_EXPOSURE not in _cats(
        "a@gmail.com, b@yahoo.com, c@acme.com and d@acme.com")


def test_single_email_not_flagged():
    assert Category.PII_EXPOSURE not in _cats("reply to me at jane@example.com")


def test_record_context_honors_any_email_domain():
    # A single customer record is PII wherever the mailbox lives — the personal-domain
    # filter applies only to the bulk contact-list heuristic.
    assert Category.PII_EXPOSURE in _cats("customer full name: Jane Roe, email jane@acme.com")


def test_source_code_leak():
    code = "def run(x):\n    import os\n    return os.system(x)"
    assert Category.SOURCE_CODE_LEAK in _cats(code)


def test_confidential_marking():
    # Marked/confidential business content -> its own category (NOT source_code_leak, so it
    # isn't suppressed for coding tools).
    assert Category.CONFIDENTIAL_DATA in _cats("This document is CONFIDENTIAL and internal use only.")


def test_sensitivity_labels():
    for marked in ("TLP:AMBER — do not forward", "Classification: Restricted",
                   "[INTERNAL] Q3 board deck", "Data Classification = Highly Confidential"):
        assert Category.CONFIDENTIAL_DATA in _cats(marked), marked
    # ordinary text with none of these is not flagged confidential
    assert Category.CONFIDENTIAL_DATA not in _cats("here are five blog title ideas")


def test_confidential_not_suppressed_for_coding_tool():
    from app.detectors.base import AnalysisInput, Surface
    from app.policy import signal_filter_for
    item = AnalysisInput(content="TLP:RED merger terms with Acme", surface=Surface.AI_USAGE,
                         channel="claude-code")
    sigs = det.analyze(item)
    filt = signal_filter_for("claude-code")
    kept = filt(sigs) if filt else sigs
    # source_code_leak would be suppressed for claude-code; confidential_data must survive.
    assert Category.CONFIDENTIAL_DATA in {s.category for s in kept}


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


def test_broadened_pii_distinctive():
    # IBAN + UK NINO flag without needing context words.
    assert Category.PII_EXPOSURE in _cats("wire to GB29NWBK60161331926819 today")
    assert Category.PII_EXPOSURE in _cats("his NI number is AB123456C")


def test_broadened_pii_context_gated():
    # These only fire WITH a nearby keyword (keeps false positives down).
    assert Category.PII_EXPOSURE in _cats("EIN 12-3456789 for the vendor")
    assert Category.PII_EXPOSURE in _cats("passport A1234567 issued 2020")
    assert Category.PII_EXPOSURE in _cats("aadhaar 1234 5678 9012")
    # …and DON'T fire on the bare number with no context word.
    assert Category.PII_EXPOSURE not in _cats("order reference 12-3456789 shipped")
    assert Category.PII_EXPOSURE not in _cats("build A1234567 completed")


def test_single_record_context():
    # A lone email/DOB is PII when it's clearly a personal record (bulk >=3 heuristic misses this).
    assert Category.PII_EXPOSURE in _cats("customer full name: Jane Roe, email jane@x.com")
    assert Category.PII_EXPOSURE in _cats("patient DOB 1985-04-12, member id 55")
    # A single email in ordinary prose (no record context) is not flagged.
    assert Category.PII_EXPOSURE not in _cats("email me at support@example.com if stuck")


def test_custom_pii_patterns_env(monkeypatch):
    monkeypatch.setenv("CUSTOM_PII_PATTERNS", "Customer ID=CUST-[0-9]{6}")
    assert Category.PII_EXPOSURE in _cats("refund for CUST-004821 please")
    assert Category.PII_EXPOSURE not in _cats("refund for order 4821 please")


def test_custom_pii_patterns_per_tenant():
    from app.detectors.shadow_ai import ShadowAIDetector
    d = ShadowAIDetector()
    item = AnalysisInput(content="record MRN1234567 for review", surface=Surface.AI_USAGE,
                         metadata={"custom_pii": "MRN=MRN\\d{7}"})
    assert Category.PII_EXPOSURE in {s.category for s in d.analyze(item)}


def test_find_secrets_shared_helper():
    assert find_secrets("password = hunter2supersecret")
    assert find_secrets("token sk-ant-abcdefghijklmnopqrstuv")
    assert find_secrets("nothing sensitive here") == []


def test_secrets_detected_with_normal_separators():
    # Canonical form -> the plain label (no evasion suffix).
    assert find_secrets("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345") == ["GitHub token"]
    assert find_secrets("glpat-ABCDEFGHIJKLMNOPQRST") == ["GitLab PAT"]
    assert find_secrets("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ["npm token"]
    assert find_secrets("sk_live_ABCDEFGHIJKLMNOP") == ["Stripe secret key"]


def test_separator_stripped_is_flagged_as_bypass():
    # Delimiter deleted to dodge DLP -> caught AND labeled as a likely bypass, exactly once.
    def one(text):
        found = find_secrets(text)
        assert len(found) == 1, found
        return found[0]
    assert one("ghpABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == "GitHub token (separator stripped — likely bypass)"
    assert one("github_patABCDEFGHIJKLMNOPQRSTUVWX") == "GitHub fine-grained PAT (separator stripped — likely bypass)"
    assert one("glpatABCDEFGHIJKLMNOPQRST") == "GitLab PAT (separator stripped — likely bypass)"
    assert one("skantabcdefghijklmnopqrstuv") == "Anthropic API key (separator stripped — likely bypass)"
    assert one("skprojABCDEFGHIJKLMNOPQRST") == "OpenAI API key (separator stripped — likely bypass)"
    assert one("npmABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == "npm token (separator stripped — likely bypass)"
    assert one("skliveABCDEFGHIJKLMNOP") == "Stripe secret key (separator stripped — likely bypass)"


def test_evasion_patterns_do_not_flag_prose():
    # The separator-stripped patterns must not fire on ordinary words/code.
    for benign in ("please skip the standup and ghost the meeting",
                   "run npm install express and start the app",
                   "the ghostwriter published a skateboarding blog",
                   "pypi and glpat are package registries we discussed",
                   "sklearn and skimage are python libraries"):
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


def test_modern_openai_dashed_keys_caught():
    # sk-proj-/sk-svcacct-/sk-admin- carry an internal dash the bare sk- pattern stops at.
    assert find_secrets("key sk-proj-aBcD1234efGh5678iJkL9012mnOpQrSt")
    assert find_secrets("sk-svcacct-Zx0192AbCdEf3456GhIjKl7890MnOp")


def test_placeholder_assignments_not_flagged_but_real_values_are():
    # Config TEMPLATES (.env.example, tutorials) must not false-positive as a secret leak.
    for template in ("API_KEY=your-api-key-here", "DB_PASSWORD=changeme", "SECRET=<your-secret>",
                     "password: placeholder", "TOKEN=${GITHUB_TOKEN}", "api_key = example"):
        assert find_secrets(template) == [], template
    # A real (non-placeholder) value in the same shape is still caught.
    assert find_secrets("password=Xk9zMp2qLw7RtY3v") == ["Credential assignment"]


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


def test_tier2_high_entropy_not_suppressed_by_client_tool():
    token = "x7Qm2Lp9Zt4Wd8Rk1Vn6Bc3Hs5Yj0FgAa2Bb"
    # The `tool` is client-asserted, so it must NOT disable secret detection — a caller
    # can't declare tool=claude-code to exfiltrate a format-less credential unflagged.
    # (Warn-level, so it doesn't hard-block routine code from a real coding assistant.)
    assert Category.SECRET_LEAK in _cats(token, channel="claude-code")
    assert Category.SECRET_LEAK in _cats(token, channel="cursor")
    # A known-prefix secret is caught regardless of tool.
    assert Category.SECRET_LEAK in _cats("AKIAIOSFODNN7EXAMPLE", channel="claude-code")


def test_custom_regex_rejects_redos_and_invalid():
    from app.detectors.patterns import _safe_custom_regex
    assert _safe_custom_regex(r"(a+)+$") is None       # nested quantifier (ReDoS)
    assert _safe_custom_regex(r"(.*)*") is None
    assert _safe_custom_regex(r"(\d+)*x") is None
    assert _safe_custom_regex(r"([unterminated") is None   # invalid regex
    assert _safe_custom_regex(r"CUST-[0-9]{6}") is not None  # safe pattern compiles


def test_confidential_terms_match_whole_words_only():
    # Regression: "nda" was a bare-substring match, so "standard"/"agenda"/"Fernanda" tripped
    # confidential_data. Must match whole words only now.
    assert Category.CONFIDENTIAL_DATA not in _cats("What is the standard format for a US SSN?")
    assert Category.CONFIDENTIAL_DATA not in _cats("review the agenda before the meeting")
    # ...but a real NDA / confidential mention still flags.
    assert Category.CONFIDENTIAL_DATA in _cats("This document is under NDA, do not share")
    assert Category.CONFIDENTIAL_DATA in _cats("CONFIDENTIAL — company proprietary material")


def test_first_party_client_destination_not_unsanctioned():
    # Regression: the local hooks label their destination "claude-code" (etc.); that's the
    # governed first-party client, not shadow AI, so it must NOT emit unsanctioned_ai.
    for client in ("claude-code", "cursor", "gemini-cli", "codex-cli"):
        assert Category.UNSANCTIONED_AI not in _cats("hello there", destination=client)
    # A real external consumer tool still flags.
    assert Category.UNSANCTIONED_AI in _cats("hello there", destination="chatgpt.com")


def test_source_code_leak_fires_on_a_lone_function():
    # A single proprietary function (def + return) should score source_code_leak even without
    # explicit "confidential/proprietary" label words.
    code = ('def calc_discount(tier, value, floor=0.34):\n'
            '    return value * (1 - floor) if tier == "enterprise" else value')
    assert Category.SOURCE_CODE_LEAK in {s.category for s in det._scan_proprietary(code)}
    # ...but ordinary prose using the words return/if/else must not.
    prose = "Please return the item if it is broken, otherwise keep it and let me know."
    assert Category.SOURCE_CODE_LEAK not in {s.category for s in det._scan_proprietary(prose)}
