"""Per-tool policy: tool detection, category suppression, signal filtering."""

from __future__ import annotations

from app import policy
from app.detectors.base import Category, Signal


def _sig(cat):
    return Signal(category=cat, title="t", detail="d", weight=0.8, confidence=0.8, detector="x")


def test_detect_tool():
    assert policy.detect_tool(user_agent="claude-cli/1.2.3") == "claude-code"
    assert policy.detect_tool(user_agent="Cursor/0.4") == "cursor"
    assert policy.detect_tool(explicit="Claude-Code") == "claude-code"
    assert policy.detect_tool(user_agent="Mozilla/5.0") == "unknown"


def test_suppressions_defaults():
    assert "source_code_leak" in policy.suppressions_for("claude-code")
    assert policy.suppressions_for("unknown") == set()


def test_env_override(monkeypatch):
    monkeypatch.setenv("GATEWAY_TOOL_SUPPRESS", "mybot:pii_exposure,source_code_leak")
    assert policy.suppressions_for("mybot") == {"pii_exposure", "source_code_leak"}


def test_signal_filter_drops_suppressed_only():
    f = policy.signal_filter_for("claude-code")
    sigs = [_sig(Category.SOURCE_CODE_LEAK), _sig(Category.SECRET_LEAK), _sig(Category.PII_EXPOSURE)]
    kept = {s.category for s in f(sigs)}
    assert Category.SOURCE_CODE_LEAK not in kept           # suppressed for a coding tool
    assert Category.SECRET_LEAK in kept and Category.PII_EXPOSURE in kept  # still flagged


def test_no_filter_for_unknown_tool():
    assert policy.signal_filter_for("unknown") is None
