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
