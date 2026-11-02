"""Documentation an agent fetches (guardrail/DLP docs, security research) quotes sample tokens and
sample contact details. Those must not read as a leak; a real-format key with a random body still
must, whatever surrounds it.

Every credential-shaped string here is assembled at runtime from fragments or generated from a
seeded RNG: none appears as a literal, so this file does not trip the scanners it tests.
"""

from __future__ import annotations

import random
import string

import pytest

from app.detectors.base import AnalysisInput, Category, Surface
from app.detectors.patterns import (_novel_chars, _synthetic_body, find_high_entropy_tokens,
                                    find_secrets)
from app.detectors.shadow_ai import ShadowAIDetector, confirmed_leak
from app.engine import engine

_RNG = random.Random(20261031)
_ALNUM = string.ascii_letters + string.digits
_B32 = string.ascii_uppercase + "234567"
_SEQ = "1234567890" + "abcdef"


def _rand(chars: str, n: int) -> str:
    return "".join(_RNG.choice(chars) for _ in range(n))


def _item(text: str) -> AnalysisInput:
    return AnalysisInput(content=text, subject="Agent tool: WebFetch", channel="WebFetch",
                         surface=Surface.AGENT_TOOLS, metadata={"tool": "WebFetch", "server": ""})


def _addr(local: str, domain: str) -> str:
    return local + "@" + domain


# --- Tier-2 entropy: typed stand-in tokens ------------------------------------------------
@pytest.mark.parametrize("tok", [
    _SEQ * 2,
    "abc123" * 5,
    "test_" + string.ascii_lowercase + "0123456789",
    "ABCDEF" + "1234567890" + "abcdef" + "123456",
])
def test_typed_stand_in_token_is_not_a_high_entropy_secret(tok):
    assert find_high_entropy_tokens(f"token {tok}") == []


def test_random_token_still_flags_as_high_entropy():
    tok = _rand(_ALNUM, 32)
    while not any(c.isdigit() for c in tok):
        tok = _rand(_ALNUM, 32)
    assert find_high_entropy_tokens(f"token {tok}")


@pytest.mark.parametrize("pad", ["1234567890" * 3, "abc123" * 6, "x" * 4])
def test_padding_a_random_token_with_a_stand_in_does_not_hide_it(pad):
    tok = _rand(_ALNUM, 20) + "7" + pad
    assert find_high_entropy_tokens(f"value {tok[:80]}")


def test_novel_chars_scores_random_bodies_at_their_length():
    for _ in range(200):
        assert _novel_chars(_rand(_ALNUM, 16), stop_above=100) >= 12


@pytest.mark.parametrize("prefix, n", [("glpat-", 20), ("pypi-", 16), ("xo" + "xb-", 10),
                                       ("AI" + "za", 35), ("sk-" + "ant-", 16), ("", 24)])
def test_random_bodies_are_never_stand_ins(prefix, n):
    # Bodies that may contain `-`/`_` must not lose random characters to prefix stripping, and a
    # short body holding one chance run must not read as typed.
    chars = _ALNUM + "-_"
    for _ in range(3000):
        assert not _synthetic_body(prefix + _rand(chars, n))


# --- Tier-1 is untouched: real-format random keys flag in any framing -----------------------
@pytest.mark.parametrize("make, label", [
    (lambda: "sk-" + _rand(_ALNUM, 32), "OpenAI API key"),
    (lambda: "AK" + "IA" + _rand(_B32, 16), "AWS access key id"),
    (lambda: "gh" + "p_" + _rand(_ALNUM, 36), "GitHub token"),
    (lambda: "sk" + "_live_" + _rand(_ALNUM, 24), "Stripe secret key"),
])
@pytest.mark.parametrize("framing", [
    "{k}",
    "For example, a key looks like {k} in the docs.",
    "```\n# example placeholder from the documentation\nKEY={k}\n```",
])
def test_random_real_format_key_still_flags_in_doc_framing(make, label, framing):
    assert label in find_secrets(framing.format(k=make()))


# --- deglued view no longer manufactures a credential assignment ----------------------------
def test_deglued_prose_is_not_a_credential_assignment():
    # A prefix-led word, then a placeholder assignment, then more prose: the deglue view used to
    # glue all of it into one `api_key=changemeplusmorewords` value, which is no placeholder.
    text = "Keys that start with " + "AK" + "IA" + " and api_key = changeme plus more words"
    assert find_secrets(text) == []
    leaks = [s for s in ShadowAIDetector().analyze(_item(text))
             if s.category == Category.SECRET_LEAK]
    assert leaks == []


def test_space_split_vendor_key_is_still_recovered():
    body = _rand(_ALNUM, 36)
    spaced = "gh" + "p_ " + " ".join(body[i:i + 4] for i in range(0, 36, 4))
    leaks = [s for s in ShadowAIDetector().analyze(_item(f"here: {spaced}"))
             if s.category == Category.SECRET_LEAK]
    assert leaks and "GitHub token" in leaks[0].evidence


# --- PII: documentation samples ----------------------------------------------------------
def _pii(text: str) -> list:
    return [s for s in ShadowAIDetector().analyze(_item(text))
            if s.category == Category.PII_EXPOSURE]


def test_reserved_example_domain_email_is_not_a_personal_record():
    text = ("To add a customer, POST their full name and email, e.g. "
            f"{{\"name\": \"Jane Doe\", \"email\": \"{_addr('jane.doe', 'example.com')}\"}}")
    assert _pii(text) == []
    assert _pii(f"customer contact: {_addr('j.smith', 'acme.test')}") == []
    assert _pii(f"member contact: {_addr('j.smith', 'mail.example.org')}") == []


def test_real_domain_email_in_a_record_still_flags():
    text = f"customer Jane Doe, email {_addr('jane.doe', 'acmecorp.io')}"
    assert any("personal record" in s.evidence for s in _pii(text))
    # A lookalike that only ends in "example.com" is a real domain.
    text = f"customer Jane Doe, email {_addr('jane.doe', 'myexample.com')}"
    assert any("personal record" in s.evidence for s in _pii(text))


def test_555_numbers_are_not_counted_as_phone_numbers():
    nums = ", ".join(f"(212) 555-01{n:02d}" for n in range(3))
    assert _pii(f"Example numbers: {nums}") == []
    assert _pii(f"customer Jane Doe, phone (212) 555-{'01'}42") == []


def test_real_phone_numbers_still_flag():
    nums = ", ".join(f"(212) 4{n}7-83{n}1" for n in range(3, 6))
    assert any("phone numbers" in s.evidence for s in _pii(f"call {nums}"))
    assert any("personal record" in s.evidence
               for s in _pii("customer Jane Doe, phone (212) 457-8301"))


# --- end to end -------------------------------------------------------------------------
def test_doc_shaped_tool_result_is_not_a_leak():
    doc = (
        "https://docs.guardrails.invalid/pii-and-secrets\n"
        "The guardrail masks personal data before it reaches the model, for example a customer\n"
        f"record with full name Jane Doe, {_addr('jane', 'example.com')}, (415) 555-0134,\n"
        f"and request tokens such as {_SEQ * 2}.\n"
        f"Support: {_addr('help', 'guardrails.invalid')}, member line (800) 555-0199\n"
    )
    v = engine.analyze(_item(doc), include_judge=False)
    assert [s for s in v.signals if s.category in (Category.SECRET_LEAK, Category.PII_EXPOSURE)] == []
    assert not confirmed_leak(v.signals)


def test_same_doc_with_a_real_key_still_blocks():
    real = "AK" + "IA" + _rand(_B32, 16)
    v = engine.analyze(_item(f"Example from the docs: AWS_ACCESS_KEY_ID={real}"),
                       include_judge=False)
    assert confirmed_leak(v.signals)
    assert v.severity in ("high", "critical")
