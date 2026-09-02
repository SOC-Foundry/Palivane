"""The shared local detector: both at-rest scanners import it, and it must return metadata
only, never the detected value."""
import importlib.util
import pathlib

# backend/tests/ -> repo root -> cli/
_MODULE = pathlib.Path(__file__).resolve().parents[2] / "cli" / "palivane_detect.py"
_spec = importlib.util.spec_from_file_location("palivane_detect", _MODULE)
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)


def _values(text):
    return [f for _, _, _, f in d.scan_all(text)]


def test_secret_is_found_and_never_returned_whole():
    key = "AKIAIOSFODNN7EXAMPLE"
    out = d.scan_all(f"AWS_ACCESS_KEY_ID={key}")
    assert out and out[0][0] == "secret_leak"
    assert key not in str(out), "the raw secret must never appear in the result"


def test_ssn_uses_ssa_structural_rules():
    assert d.scan_all("ssn 412-88-7390")            # valid
    assert not d.scan_all("ssn 000-88-7390")        # area 000
    assert not d.scan_all("ssn 666-88-7390")        # area 666
    assert not d.scan_all("ssn 412-00-7390")        # group 00


def test_unformatted_ssn_needs_context():
    assert d.scan_all("ssn 412887390")
    assert not d.scan_all("order 412887390")


def test_card_needs_luhn_and_test_pans_only_suppressed_when_illustrative():
    assert d.scan_all("card 4539578763621486")              # real, Luhn-valid
    assert not d.scan_all("card 4539882144718033")          # fails Luhn
    assert not d.scan_all("e.g. 4242424242424242")          # documented PAN, illustrative
    assert d.scan_all("charge the card 4242424242424242")   # same PAN, transactional


def test_health_context_promotes_pii_to_phi():
    cats = {c for c, _, _, _ in d.scan_all("patient diagnosis ssn 412-88-7390")}
    assert cats == {"phi_exposure"}
    cats = {c for c, _, _, _ in d.scan_all("customer ssn 412-88-7390")}
    assert cats == {"pii_exposure"}


def test_ambiguous_identifiers_are_gated_on_a_keyword():
    assert d.scan_all("routing 021000021")
    assert not d.scan_all("021000021")


def test_masked_previews_hide_the_middle():
    m = d.mask("ghp_abcdefghijklmnop1234")
    assert m.startswith("ghp_") and m.endswith("1234") and "•" in m
    assert "abcdefghijklmnop" not in m


def test_clean_text_produces_nothing():
    assert d.scan_all("just some ordinary prose about buckets") == []


# --- AWS secret access key ----------------------------------------------------------------
# The id half (AKIA…) was always caught; the SECRET half had no pattern here at all. The
# server gained one in #234 after a real 40-char secret survived redaction and was stored
# verbatim, but the fix never reached this module, so both at-rest scanners stayed blind to
# exactly the credential the sweep exists to find.

_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_aws_secret_access_key_is_detected():
    out = d.scan_all(f"aws_secret_access_key={_AWS_SECRET}")
    assert [lbl for _, lbl, _, _ in out] == ["AWS secret access key"]
    assert _AWS_SECRET not in str(out)


def test_aws_secret_preview_masks_the_value_not_the_label():
    """The pattern has to match the surrounding "secret_access_key" label to identify the
    value, but the preview must be of the value — otherwise it reads 'secr••••EKEY'."""
    (_, _, _, masked), = d.scan_all(f"aws_secret_access_key={_AWS_SECRET}")
    assert masked.startswith("wJal") and masked.endswith("EKEY")


def test_aws_secret_spellings():
    for line in (f'secret_key = "{_AWS_SECRET}"',
                 f"aws secret access key: {_AWS_SECRET}",
                 f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}"):
        assert any(lbl == "AWS secret access key" for _, lbl, _, _ in d.scan_all(line)), line


def test_bare_base64_run_is_not_an_aws_secret():
    """Ungated, the 40-char pattern would match any base64 blob. A digest still trips the
    generic entropy backstop, but must not be mislabelled as an AWS credential."""
    out = d.scan_all("digest = 4k2L9xQ/vB8mN3pR7sT1uW5yZ0aC6eG2hJ4kM8nP")
    assert not any(lbl == "AWS secret access key" for _, lbl, _, _ in out)


def test_aws_secret_placeholder_is_not_reported():
    assert not d.scan_all("aws_secret_access_key=your-secret-key-here")


# --- redact() ------------------------------------------------------------------------------
# For payloads that must be sent somewhere for analysis that does not need the value: the
# structural shape survives, the credential does not.

_GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_MCP = ('{"mcpServers": {"github": {"command": "npx", "args": ["-y", "server-github"],'
        ' "env": {"GITHUB_TOKEN": "%s"}}}}' % _GH)


def test_redact_removes_the_value_and_keeps_the_structure():
    out = d.redact(_MCP)
    assert _GH not in out
    assert "«redacted:GitHub token»" in out
    # everything the backend actually vets is still there
    assert '"command": "npx"' in out and "server-github" in out and '"github"' in out


def test_redact_output_is_still_parseable_json():
    import json
    j = json.loads(d.redact(_MCP))
    assert j["mcpServers"]["github"]["command"] == "npx"


def test_redact_removes_every_occurrence_not_just_the_first():
    """scan_text reports a repeated value once; leaving the other copies would defeat it."""
    out = d.redact(f"a={_GH}\nb={_GH}\nc={_GH}\n")
    assert _GH not in out and out.count("«redacted:") == 3


def test_redact_leaves_ordinary_values_alone():
    text = '{"env": {"TENANT_ID": "acme-prod", "REGION": "us-east-1"}}'
    assert d.redact(text) == text


def test_redact_catches_an_opaque_token_via_the_entropy_backstop():
    opaque = "7fQ2mNvR8sLpXd3JhTgB6wYzKc1AeUiO"
    assert opaque not in d.redact('{"env": {"ACME_SERVICE_KEY": "%s"}}' % opaque)


def test_redact_finds_what_scan_finds():
    """The two must agree: a value scan_text reports has to be one redact removes, or the
    payload would carry a secret the sender has already told the server about."""
    text = (f"github={_GH}\naws=AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "db=postgres://u:sup3rsecret@host/db\n")
    out = d.redact(text)
    for value in (_GH, "AKIAIOSFODNN7EXAMPLE",
                  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "sup3rsecret"):
        assert value not in out, value
    assert len(d.scan_text(text)) >= 4


# --- reversible tokenization -----------------------------------------------------------
# The point of tokenizing rather than redacting is that the prompt still works, so these
# check that structure survives, identity does not, and nothing is left behind afterwards.

def test_tokenize_round_trips():
    text = "Customer SSN 123-45-6789 on card 4242424242424242."
    tok, m = d.tokenize(text)
    assert "123-45-6789" not in tok and "4242424242424242" not in tok
    assert d.detokenize(tok, m) == text


def test_the_same_value_gets_the_same_token():
    """A model must still be able to tell that two mentions are the same person."""
    tok, m = d.tokenize("SSN 123-45-6789 ... about SSN 123-45-6789")
    tokens = d.TOKEN_RE.findall(tok)
    assert len(tokens) == 2 and tokens[0] == tokens[1]
    assert len(m) == 1


def test_different_values_get_different_tokens():
    # Both must be VALID SSNs: 900-999 and 666 are unassigned areas and _valid_ssn9
    # rejects them, which is the detector being right rather than the tokenizer failing.
    tok, m = d.tokenize("SSN 123-45-6789 and SSN 234-56-7890")
    assert len(set(d.TOKEN_RE.findall(tok))) == 2 and len(m) == 2


def test_the_token_says_what_kind_of_value_it_replaced():
    """Structure is the whole point: the model should know it is holding a card, not a name."""
    tok, _ = d.tokenize("card 4242424242424242")
    assert "PCN" in tok


def test_secrets_are_not_tokenized():
    """A credential must not reach the model in any form, so redact() stays the answer."""
    text = "aws key AKIAIOSFODNN7EXAMPLE"
    tok, m = d.tokenize(text)
    assert tok == text and m == {}


def test_detokenize_survives_a_model_changing_case():
    tok, m = d.tokenize("SSN 123-45-6789")
    token = next(iter(m))
    assert d.detokenize(f"about {token.lower()} here", m) == "about 123-45-6789 here"


def test_an_invented_token_is_left_alone_and_reported():
    """A model that makes up a token is telling you something; deleting it hides that."""
    _, m = d.tokenize("SSN 123-45-6789")
    out = d.detokenize("see PLV_USSN_ABCDEF", m)
    assert out == "see PLV_USSN_ABCDEF"
    assert d.unknown_tokens(out, m) == ["PLV_USSN_ABCDEF"]


def test_a_shorter_value_inside_a_longer_one_cannot_strand_a_fragment():
    tok, m = d.tokenize("card 4242424242424242 and SSN 123-45-6789")
    assert not any(ch.isdigit() for ch in tok.replace("PLV_", "").split("SSN")[0]
                   if ch in "4242424242424242") or "4242424242424242" not in tok
    assert d.detokenize(tok, m).count("4242424242424242") == 1


def test_nothing_is_returned_that_a_caller_could_accidentally_persist():
    """The map is the only place a raw value appears, and it is a return value the caller
    holds in memory. scan_all's invariant (metadata only) is unaffected by the split."""
    text = "SSN 123-45-6789"
    assert all("123-45-6789" not in str(f) for f in d.scan_all(text))
