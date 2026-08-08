"""False-positive-class guards for the secret detectors, from the real-OSS-repo benchmark
(tools/fp_benchmark). Each test pins a class of code that must NOT read as a secret, paired
with a recall guard so the fix never silently suppresses a real credential."""
from __future__ import annotations

from app.detectors.patterns import find_high_entropy_tokens, find_secrets


# --- Tier-2 entropy: code identifiers are not secrets -----------------------------------

def test_dictionary_camelcase_identifiers_not_flagged():
    for ident in ("OAuth2PasswordRequestForm", "getOwnPropertyDescriptor",
                  "SecureCookieSessionInterface", "TemplateContextProcessor"):
        assert find_high_entropy_tokens(ident) == [], ident


def test_all_letter_identifier_not_flagged():
    # No digit → cannot be the generic high-entropy heuristic's business.
    assert find_high_entropy_tokens("StarletteBackgroundTaskRunner") == []


def test_real_random_token_still_flagged():
    # Digit-bearing, not word-structured: a genuine novel token must still surface.
    tok = "a3F9kZ2mQ8xR7tW4yB6nP1sD5vG0hJ"
    assert find_high_entropy_tokens(tok), "recall regression: random token no longer flagged"


def test_certificate_body_not_flagged_but_private_key_is():
    cert = ("-----BEGIN CERTIFICATE-----\n"
            "MIIC8zCCAdugAwIBAgIJAKZ7D0aQ2mA1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwX\n"
            "YzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz\n"
            "-----END CERTIFICATE-----\n")
    assert find_high_entropy_tokens(cert) == []
    assert "Private key block" in find_secrets(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")


# --- Credential assignment: expressions are references, not hardcoded secrets -----------

def test_expression_valued_assignments_not_flagged():
    for code in ('password = request.form["pw"]', "secret = self.get_secret()",
                 "api_key = config.API_KEY", "access_token = os.environ['TOK']",
                 "client_secret = settings.secret"):
        assert "Credential assignment" not in find_secrets(code), code


def test_hardcoded_literal_assignment_still_flagged():
    # A literal value IS a hardcoded secret — must still fire (recall guard).
    assert "Credential assignment" in find_secrets('password = "hunter2hunter2xyz"')
    assert "Credential assignment" in find_secrets("api_key = 's3cr3t-l1teral-value-9x'")


# --- known-format secrets are untouched by any of the above -----------------------------

def test_known_format_secrets_still_detected():
    assert "AWS access key id" in find_secrets("key = AKIAIOSFODNN7EXAMPLE")
    assert "GitHub token" in find_secrets("t = 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")
    assert "Stripe secret key" in find_secrets("k = sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH")
