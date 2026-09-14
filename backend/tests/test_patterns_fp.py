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


# --- path allowlist: demote generic matches in test/docs/example paths --------------------

from app.detectors.patterns import is_low_signal_path, only_generic_secrets  # noqa: E402


def test_low_signal_path_classification():
    for p in ("tests/test_x.py", "src/pkg/__tests__/a.js", "docs/guide.md",
              "examples/demo.py", "fixtures/data.json", "vendor/lib/x.go",
              "node_modules/pkg/i.js", "app/foo.md", "conftest.py", "a_test.go"):
        assert is_low_signal_path(p), p
    for p in ("src/app/config.py", "main.go", "lib/client.rb", "app/auth.py"):
        assert not is_low_signal_path(p), p


def test_only_generic_secrets_classification():
    assert only_generic_secrets(["Credential assignment"])
    assert only_generic_secrets(["JWT", "Credential assignment"])
    assert not only_generic_secrets(["AWS access key id"])
    assert not only_generic_secrets(["Credential assignment", "AWS access key id"])
    assert not only_generic_secrets([])


def _secret_flagged(content, subject, channel):
    from app.detectors.base import AnalysisInput, Surface
    from app.detectors.shadow_ai import ShadowAIDetector
    sigs = ShadowAIDetector().analyze(
        AnalysisInput(content=content, subject=subject, channel=channel, surface=Surface.AI_USAGE))
    return any(s.category.value == "secret_leak" for s in sigs)


def test_allowlist_demotes_generic_only_in_low_signal_file_paths():
    # generic hardcoded credential: suppressed in a test path, kept in production code
    assert not _secret_flagged('password = "hunter2hunter2"', "tests/test_x.py", "git")
    assert _secret_flagged('password = "hunter2hunter2"', "src/app/config.py", "git")


def test_allowlist_never_demotes_distinctive_keys():
    # a real vendor key leaks wherever it is — test path or not
    assert _secret_flagged('k = "AKIAIOSFODNN7EXAMPLE"', "tests/test_x.py", "git")


def test_allowlist_never_applies_to_prompt_channels():
    # subject on a prompt isn't a path; a secret in a prompt must always flag
    assert _secret_flagged('password = "hunter2hunter2"', "tests/test_x.py", "claude-code")
    assert _secret_flagged('password = "hunter2hunter2"', "whatever", "gateway")


# --- request-scoped secret-pass cache (perf; must not change results) --------------------

def test_secret_labels_cache_memoizes_and_matches():
    from app.detectors.base import AnalysisInput, Surface
    from app.detectors.patterns import find_secrets
    item = AnalysisInput(content='key = "AKIAIOSFODNN7EXAMPLE"', subject="config.py",
                         channel="git", surface=Surface.AI_USAGE)
    first = item.secret_labels()
    assert first is item.secret_labels()                      # memoized: same object
    assert first == find_secrets("config.py\n" + 'key = "AKIAIOSFODNN7EXAMPLE"')
    assert "AWS access key id" in first                        # recall intact


# --- Tier-2 entropy: provider ids, public keys, word runs -------------------------------
# Measured against production data 2026-08-18: the generic entropy heuristic was ~36% of all
# findings, and its evidence was dominated by AI-provider correlation ids, base64 public keys
# and prose — not credentials. Each class below is pinned with a recall guard alongside.

def test_provider_correlation_ids_not_flagged():
    # A tool_use / request / message id is emitted once per AI tool call: prefix + random
    # suffix, so it clears every entropy gate while carrying no credential.
    for tok in ("toolu_01VWabcdEFgh2345IJklMNop",
                "req_011CeQwErTy456UiOpAsDf789",
                "msg_01A9bCdEfGhIjKlMnOpQrStU",
                "call_9aBcDeFgHiJkLmNoPqRsTuVw",
                "chatcmpl-9xYzAbCdEfGh12345678",
                "thread_abc123DEF456ghi789JKL"):
        assert find_high_entropy_tokens(tok) == [], tok


def test_dotted_suffix_identifiers_not_flagged():
    # A high-entropy stem immediately followed by a short dotted suffix is a filename,
    # hostname, or dotted id (module path, bundle name) — not a credential. These flooded
    # the console as false high-entropy criticals from skill docs and build output.
    for tok in ("aB3kZ9qWmX7vP2.js",
                "x7Kp2mQ9wZ4nR8.min.css",
                "d41d8cd98f00b204e9800998.chunk.js",
                "kf83jdLm29xQ.internal.example.com"):
        assert find_high_entropy_tokens(tok) == [], tok


def test_bare_base64_public_keys_not_flagged():
    # PEM-armoured public keys were already masked; MCP/JSON payloads carry the bare SPKI
    # body with no -----BEGIN----- header. A PUBLIC key is not a secret.
    for tok in ("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq7Bt3xY9zK2mNpQ4",   # EC P-256
                "MCowBQYDK2VwAyEA1x9KpQ7mZ4nB6cF2hJ5sD0gAtR8vL3yW7uX",   # Ed25519
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2xK9mQ"):   # RSA-2048
        assert find_high_entropy_tokens(tok) == [], tok


def test_private_key_body_still_flagged_despite_public_key_guard():
    # Recall guard for the rule above: the PRIVATE half must never be suppressed.
    assert "Private key block" in find_secrets(
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIF7q1x9KpQ7mZ4nB6cF2\n-----END EC PRIVATE KEY-----")


def test_concatenated_word_runs_not_flagged():
    # Prose with no camelCase or underscore boundary: _ID_SEGMENT_RE sees one long segment,
    # so the camelCase dictionary check cannot fire. These come from docs and comments.
    for tok in ("1whenthisdocumentwasreviewed",
                "thequickbrownfoxjumpsoverthelazydog7",
                "seetheconfigurationsectionbelow2"):
        assert find_high_entropy_tokens(tok) == [], tok


def test_random_secrets_still_flagged_after_new_guards():
    # The recall contract for all three guards above: high-entropy tokens that do NOT look
    # like an id, a public key or prose must still surface.
    for tok in ("TWz8wkfno8vQ2xR7pL4mB9cD1sG5hJ3k",     # bare random
                "8cV_prtHmvK2wQ9zL4nB7cF1hJ5sD0gA",     # random with underscore
                "ak_hI28ffF8htyVLy1Wy4GrwYPz9pid4",     # prefixed but genuinely a key
                "asdkj23kjh12qwe89rty45uio77zxc"):      # keyboard mash
        assert find_high_entropy_tokens(tok), f"recall regression: {tok}"


# --- AWS secret access key: the half with no prefix -------------------------------------

def test_aws_secret_access_key_detected_and_redacted():
    """The SECRET half of an AWS credential pair was invisible to every layer.

    Found 2026-08-18 by posting a real credential pair through /api/ingest/ai-usage and
    reading the stored row: the AKIA id and the SSN were masked, the 40-char secret was
    persisted verbatim. No Tier-1 pattern covered it, and the entropy backstop structurally
    cannot — _TOKEN_CANDIDATE_RE is [A-Za-z0-9_]{24,80}, so a base64 secret's "/" splits it
    into sub-24-char pieces. Since redact_text() iterates SECRET_PATTERNS, detecting it is
    what makes it redactable.
    """
    from app.redaction import redact_text
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    sample = f"deploy with AWS key AKIAIOSFODNN7EXAMPLE and secret {secret} plus ssn 078-05-1120"
    found = find_secrets(sample)
    assert "AWS secret access key" in found
    assert "AWS access key id" in found          # the pair, not one or the other
    out = redact_text(sample)
    assert secret not in out, "the secret survived redaction"
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "078-05-1120" not in out


def test_aws_secret_spellings_all_detected():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    for text in (f"aws_secret_access_key={secret}",          # "_" is a word char: needs a
                 f"AWS Secret Access Key: {secret}",         # lookbehind, not \b
                 f"secret-key {secret}",
                 f'"SecretAccessKey": "{secret}"'):
        assert "AWS secret access key" in find_secrets(text), text


def test_bare_base64_without_a_secret_label_is_not_an_aws_secret():
    # The value alone is indistinguishable from any 40-char base64 run, so the label gates it.
    for text in ("integrity 9f2b7c1de4a08356bb17f0c9d4e2a1f8c33b6e5a7d90142f",
                 "payload dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBs",
                 "keep this secret, please do not share it with anyone at all",
                 "kind: Secret\nmetadata:\n  name: my-app-credentials-config"):
        assert "AWS secret access key" not in find_secrets(text), text
