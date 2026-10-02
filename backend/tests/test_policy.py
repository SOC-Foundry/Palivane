"""Per-tool policy: tool detection, category suppression, signal filtering."""

from __future__ import annotations

from app import policy
from app.detectors.base import Category, Signal


def _sig(cat):
    return Signal(category=cat, title="t", detail="d", weight=0.8, confidence=0.8, detector="x")


def test_detect_tool():
    assert policy.detect_tool(user_agent="claude-cli/1.2.3") == "claude-code"
    assert policy.detect_tool(user_agent="Cursor/0.4") == "cursor"
    assert policy.detect_tool(user_agent="GeminiCLI/0.1.0") == "gemini-cli"
    assert policy.detect_tool(explicit="Claude-Code") == "claude-code"
    assert policy.detect_tool(user_agent="Mozilla/5.0") == "unknown"


def test_suppressions_defaults():
    assert "source_code_leak" in policy.suppressions_for("claude-code")
    assert "source_code_leak" in policy.suppressions_for("gemini-cli")
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


# --- suppression keyed by where the prompt is going --------------------------------------
#
# A coding assistant is recognised by its User-Agent, so `claude-code:source_code_leak` works
# for it. A web assistant has none: a prompt typed into claude.ai carries no tool name, so the
# tool-keyed rule could not be aimed at it, and the only handle left, "unknown", covers every
# untagged capture including the ones going to tools nobody approved. A key that is a host
# reaches it by destination instead, on whole labels like the sanctioned list.

def test_a_host_key_covers_that_host_and_its_subdomains():
    spec = "claude.ai:source_code_leak"
    for dest in ("https://claude.ai/chat/abc", "claude.ai", "https://www.claude.ai",
                 "CLAUDE.AI:443/new", "wss://api.claude.ai/socket"):
        assert policy.suppressions_for_destination(dest, spec) == {"source_code_leak"}, dest


def test_a_host_key_does_not_cover_lookalikes():
    spec = "claude.ai:source_code_leak"
    for dest in ("https://claude.ai.evil.example", "https://notclaude.ai",
                 "https://evil.example/claude.ai", "https://claude.ai@evil.example/",
                 "https://chatgpt.com", ""):
        assert policy.suppressions_for_destination(dest, spec) == set(), dest


def test_a_key_without_a_dot_is_a_tool_id_not_a_host():
    # `cursor` and `claude-code` are tool ids; they keep working through suppressions_for and
    # are not reinterpreted as hostnames.
    assert policy.suppressions_for_destination("cursor", "cursor:pii_exposure") == set()
    assert "pii_exposure" in policy.suppressions_for("cursor", "cursor:pii_exposure")


def test_host_rules_come_from_the_deployment_setting_too(monkeypatch):
    monkeypatch.setenv("GATEWAY_TOOL_SUPPRESS", "claude.ai:source_code_leak")
    assert policy.suppressions_for_destination("https://claude.ai") == {"source_code_leak"}


def test_the_filter_applies_host_rules_next_to_tool_rules():
    f = policy.signal_filter_for("unknown", extra="claude.ai:source_code_leak",
                                 destination="https://claude.ai/chat")
    sigs = [_sig(Category.SOURCE_CODE_LEAK), _sig(Category.SECRET_LEAK)]
    kept = {s.category for s in f(sigs)}
    assert kept == {Category.SECRET_LEAK}                  # code is expected there; a key is not
    # another destination gets no filter at all, and a coding assistant keeps its default
    assert policy.signal_filter_for("unknown", extra="claude.ai:source_code_leak",
                                    destination="https://chatgpt.com") is None
    g = policy.signal_filter_for("claude-code", extra="claude.ai:pii_exposure",
                                 destination="https://api.anthropic.com")
    assert Category.SOURCE_CODE_LEAK not in {s.category for s in g(sigs)}
