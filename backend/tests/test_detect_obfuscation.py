"""cli/palivane_detect.py: look-alike folding and decode-and-rescan in the at-rest scanners.

Every value here is assembled at runtime from fragments, so no complete credential or
identifier sits in the source.
"""
from __future__ import annotations

import base64
import gzip
import importlib.util
import random
import string
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "cli" / "palivane_detect.py"
_spec = importlib.util.spec_from_file_location("palivane_detect_obf", _PATH)
detect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect)

_rnd = random.Random(1234)
_TOKEN = "gh" + "p" + "_" + "".join(_rnd.choice(string.ascii_letters + string.digits)
                                    for _ in range(36))
_KEY_ID = "AK" + "IA" + "".join(_rnd.choice(string.ascii_uppercase + string.digits)
                                for _ in range(16))
_SSN = "07" + "8-0" + "5-11" + "20"


def _fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _labels(text: str) -> set[str]:
    return {label for _cat, label, _ln, _masked in detect.scan_all(text)}


CASES = [
    ("fullwidth", lambda: "export GH=" + _fullwidth(_TOKEN), "GitHub token" + detect._FOLDED),
    ("zero_width", lambda: "key " + "​".join(_KEY_ID), "AWS access key id" + detect._FOLDED),
    ("cyrillic", lambda: "export GH=" + _TOKEN.replace("p", "р", 1),
     "GitHub token" + detect._FOLDED),
    ("base64", lambda: "data: " + _b64("token " + _TOKEN), "GitHub token" + detect._ENCODED),
    ("gzip_base64", lambda: "blob " + base64.b64encode(gzip.compress(("x " + _TOKEN).encode())).decode(),
     "GitHub token" + detect._ENCODED),
    ("nested_base64", lambda: "v " + _b64(_b64("note " + _TOKEN)), "GitHub token" + detect._ENCODED),
    ("unicode_escapes", lambda: "s = '" + "".join(f"\\u{ord(c):04x}" for c in _TOKEN) + "'",
     "GitHub token" + detect._ENCODED),
    ("ssn_fullwidth", lambda: "SSN " + _fullwidth(_SSN),
     "US Social Security number" + detect._FOLDED),
    ("ssn_base64", lambda: "x " + _b64("ssn " + _SSN), "US Social Security number" + detect._ENCODED),
]


@pytest.mark.parametrize("make,label", [(m, lbl) for _n, m, lbl in CASES],
                         ids=[n for n, _m, _l in CASES])
def test_hidden_values_are_found(make, label):
    assert label in _labels(make())


def test_a_plain_value_is_reported_once_without_a_suffix():
    found = detect.scan_text(f"export GH={_TOKEN}\nagain {_b64('token ' + _TOKEN)}")
    assert [label for label, _ln, _m in found] == ["GitHub token"]


def test_benign_text_gains_nothing():
    benign = "\n".join([
        "The internationalization committee approved the proposal.",
        "Café naïve résumé — ﬁne ① ｆｕｌｌｗｉｄｔｈ prose",
        "url https://example.com/search?q=hello%20world&lang=en",
        "commit " + "".join(_rnd.choice("0123456789abcdef") for _ in range(40)),
        "img data:image/png;base64," + base64.b64encode(bytes(range(256)) * 2).decode(),
    ])
    # The plain entropy check has its own opinion of a data URI; the new views add nothing.
    assert not [lbl for lbl in _labels(benign)
                if lbl.endswith((detect._FOLDED, detect._ENCODED))]


def test_redact_removes_what_holds_a_hidden_value():
    text = "\n".join(["A=" + _fullwidth(_TOKEN), "B: " + _b64("token " + _TOKEN),
                      "C=%20" + _TOKEN, "D=keep"])
    out = detect.redact(text)
    for leaked in (_TOKEN, _fullwidth(_TOKEN), _b64("token " + _TOKEN)):
        assert leaked not in out
    lines = out.splitlines()
    assert lines[2].startswith("C=")       # a plain value is cut out, not its whole line
    assert lines[3] == "D=keep"


def test_an_over_budget_text_is_reported_partial():
    blob = base64.b64encode(bytes(_rnd.getrandbits(8) for _ in range(3000))).decode()
    _found, partial = detect.scan_all_detail("\n".join("v " + blob for _ in range(200)))
    assert partial
    assert detect.scan_all_detail("v " + _b64("token " + _TOKEN))[1] is False
