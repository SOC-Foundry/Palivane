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


# --- Tier-2 entropy: a base64 attachment is a file, not a pile of credentials ------------
# One screenshot pasted into claude.ai produced 21 separate high-severity findings, because
# the transports carry an image as a bare JSON field (no `data:` URI for the blob rule to
# match) and the entropy scan shredded the body into "tokens". Every finding quoted the same
# JPEG/ICC fragments — evidence that repeats byte-identically across findings is a file
# format. Paired with recall guards: the mask must not become a place to hide a key.

def _b64(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode()


_JPEG = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
         b"\xff\xdb\x00C\x00" + bytes(range(256)) * 8)
_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)) * 8


def test_json_carried_base64_image_is_not_a_pile_of_secrets():
    import json
    for media, raw in (("image/jpeg", _JPEG), ("image/png", _PNG)):
        payload = json.dumps({"type": "image",
                              "source": {"type": "base64", "media_type": media,
                                         "data": _b64(raw)}})
        assert find_high_entropy_tokens(payload) == [], media


def test_data_uri_image_still_masked():
    # The pre-existing blob rule keeps working; the new magic-based span is additive.
    assert find_high_entropy_tokens("data:image/jpeg;base64," + _b64(_JPEG)) == []


def test_pdf_and_zip_attachments_not_flagged():
    for raw in (b"%PDF-1.7\n" + bytes(range(256)) * 8,
                b"PK\x03\x04\x14\x00" + bytes(range(256)) * 8):
        assert find_high_entropy_tokens(_b64(raw)) == []


def test_secret_next_to_an_attachment_still_flagged():
    # Recall: masking the attachment must not mask the message it travels in.
    import json
    payload = json.dumps({"source": {"type": "base64", "data": _b64(_JPEG)},
                          "note": "deploy with xQ3mZp8Wd2Lk9Rt4Vb7Nc1Hj5Fs6Gy0A"})
    assert any(t.startswith("xQ3mZp8Wd2") for t in find_high_entropy_tokens(payload))


def test_base64_without_a_media_magic_is_still_scanned():
    # Recall: only a run whose decoded head IS a known container gets masked. A long random
    # base64 blob — the shape of an actual exfiltrated key — must not ride through by length.
    import base64
    blob = base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(400))).decode()
    assert find_high_entropy_tokens(blob), "recall regression: bare base64 no longer scanned"


def test_named_format_secret_hidden_inside_a_fake_image_still_caught():
    # The mask is scoped to the Tier-2 entropy heuristic on purpose: wrapping a key in
    # something shaped like a JPEG must not buy an attacker anything at Tier 1.
    payload = _b64(_JPEG) + " ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    assert any("GitHub" in lbl for lbl in find_secrets(payload)), find_secrets(payload)


# --- Tier-1 evasion variants: a separator-stripped pattern is chance-prone in base64 -------
# `gh[pousr][A-Za-z0-9]{30,}` is four literal characters and a permissive class, so it hits by
# chance roughly 11 times per megabyte of base64. On 8 MiB of random bytes with no credential
# in them at all, the GitHub and npm variants fired on 8 of 8 blobs (measured 2026-09-22); in
# production that turned pasted screenshots into critical findings labelled "likely bypass".

def test_evasion_variants_do_not_fire_inside_an_attachment():
    import json
    payload = json.dumps({"source": {"type": "base64", "media_type": "image/jpeg",
                                     "data": _b64(_JPEG + bytes(range(256)) * 400)}})
    assert [lbl for lbl in find_secrets(payload) if "separator stripped" in lbl] == []


def test_canonical_key_inside_the_same_payload_still_caught():
    # Recall: the exemption is for the EVASION tier only. A canonical token keeps its
    # separator, which is specific enough to survive a blob, so it must still fire.
    import json
    payload = json.dumps({"source": {"type": "base64", "data": _b64(_JPEG)},
                          "note": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"})
    assert "GitHub token" in find_secrets(payload)


def test_separator_stripped_token_in_prose_still_flagged():
    # Recall: the evasion tier exists to catch a real DLP bypass, and outside an attachment
    # it still does.
    labels = find_secrets("here you go: ghpA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7 use it")
    assert any("separator stripped" in lbl for lbl in labels), labels


# --- Upstream attachment stripping -------------------------------------------------------

def test_strip_media_blobs_replaces_attachment_with_a_placeholder():
    import json
    from app.detectors.patterns import ATTACHMENT_PLACEHOLDER, strip_media_blobs
    payload = json.dumps({"source": {"media_type": "image/jpeg", "data": _b64(_JPEG)},
                          "note": "see attached"})
    out = strip_media_blobs(payload)
    assert ATTACHMENT_PLACEHOLDER in out and "see attached" in out
    assert len(out) < len(payload) // 4


def test_strip_media_blobs_leaves_ordinary_text_alone():
    from app.detectors.patterns import strip_media_blobs
    text = "nothing to see here, just prose with a sha256-abc hash"
    assert strip_media_blobs(text) is text
