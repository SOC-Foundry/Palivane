"""The email pattern must stay linear on attacker-sized input: unbounded, a long run of word
characters and dots with no '@' took minutes per scan (and clients fail open on timeout)."""
from __future__ import annotations

import importlib.util
import pathlib
import time

import pytest

from app.detectors.shadow_ai import EMAIL_RE as SERVER_RE

_cli = pathlib.Path(__file__).resolve().parents[2] / "cli" / "palivane_detect.py"
_spec = importlib.util.spec_from_file_location("palivane_detect_for_test", _cli)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


@pytest.mark.parametrize("rx", [SERVER_RE, _mod.EMAIL_RE], ids=["server", "client"])
@pytest.mark.parametrize("filler", ["a.", "ab-cd+", "1.2.3."])
def test_no_quadratic_backtracking(rx, filler):
    s = filler * (200_000 // len(filler))              # the analysis cap, no '@' anywhere
    t = time.perf_counter()
    rx.findall(s)
    assert time.perf_counter() - t < 1.0               # was minutes


@pytest.mark.parametrize("rx", [SERVER_RE, _mod.EMAIL_RE], ids=["server", "client"])
def test_still_matches_real_addresses(rx):
    text = "write to jane.doe+tag@corp-mail.co or ops@sub.example.org, not bad@nodot"
    assert rx.findall(text) == ["jane.doe+tag@corp-mail.co", "ops@sub.example"]
