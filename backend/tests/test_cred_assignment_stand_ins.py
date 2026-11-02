"""Credential assignment with a typed stand-in value (docs samples) vs. a real-looking one.
Values are built from fragments so no literal credential sits in this file."""
from __future__ import annotations

import secrets

import pytest

from app.detectors.patterns import find_secrets

LABEL = "Credential assignment"
RUNS = "1234567890" + "abcdef" + "1234567890" + "abcdef"
MIXED_RUNS = "abcdefghij" + "ABCDEFGHIJ" + "0123456789"


def _random(n: int = 32) -> str:
    out = ""
    while len(out) < n:
        out += "".join(c for c in secrets.token_urlsafe(n) if c.isalnum())
    return out[:n]


@pytest.mark.parametrize("text", [
    "X-Api-Token: " + RUNS,
    "api_key = \"" + RUNS + "\"",
    "auth_token=" + MIXED_RUNS,
    "client_secret: " + "abc123" * 5,
])
def test_issued_credential_with_typed_value_is_a_sample(text):
    assert LABEL not in find_secrets(text)


@pytest.mark.parametrize("text", [
    "X-Api-Token: " + _random(),
    "api_key = \"" + _random() + "\"",
    # padding a real token with a run does not hide its own random characters
    "auth_token=" + RUNS + _random(16),
])
def test_random_value_still_flags(text):
    assert LABEL in find_secrets(text)


@pytest.mark.parametrize("lhs", ["password", "db_password", "DB_PASSWD", "pwd"])
def test_password_with_typed_value_still_flags(lhs):
    # people choose passwords, and sequences are what they choose
    assert LABEL in find_secrets(lhs + " = " + "abc123" * 3)
