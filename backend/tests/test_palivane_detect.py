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
