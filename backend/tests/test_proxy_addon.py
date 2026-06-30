"""Egress-proxy addon: host matching, prompt extraction, block decision (pure logic)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "warden_addon", Path(__file__).resolve().parents[2] / "proxy" / "warden_addon.py")
addon = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(addon)


def test_is_ai_host():
    assert addon.is_ai_host("api.anthropic.com")
    assert addon.is_ai_host("api.openai.com")
    assert addon.is_ai_host("claude.ai")
    assert addon.is_ai_host("generativelanguage.googleapis.com")
    assert not addon.is_ai_host("example.com")
    assert not addon.is_ai_host("")


def test_is_ai_host_copilot():
    # GitHub Copilot (IDE) — api + business/individual variants share the suffix.
    assert addon.is_ai_host("api.githubcopilot.com")
    assert addon.is_ai_host("api.business.githubcopilot.com")
    assert addon.is_ai_host("api.individual.githubcopilot.com")
    assert addon.is_ai_host("copilot-proxy.githubusercontent.com")
    # Microsoft Copilot (web / desktop).
    assert addon.is_ai_host("copilot.microsoft.com")
    # A lookalike that isn't actually Copilot must not match.
    assert not addon.is_ai_host("notgithubcopilot.example.com")


def test_detect_tool_copilot():
    # GitHub Copilot's IDE clients identify themselves in the User-Agent.
    assert addon.detect_tool("GitHubCopilotChat/0.12 VSCode") == "copilot"
    assert addon.detect_tool("github-copilot/1.0") == "copilot"


def test_extract_openai_chat():
    body = json.dumps({"messages": [
        {"role": "system", "content": "be helpful"},
        {"role": "user", "content": "my SSN is 123-45-6789"},
        {"role": "assistant", "content": "ok"},
    ]})
    out = addon.extract_prompt(body)
    assert "123-45-6789" in out
    assert "ok" not in out  # assistant turns excluded


def test_extract_chatgpt_web_shape():
    body = json.dumps({"messages": [
        {"author": {"role": "user"}, "content": {"parts": ["leak AKIAABCDEFGHIJKLMNOP"]}}
    ]})
    assert "AKIAABCDEFGHIJKLMNOP" in addon.extract_prompt(body)


def test_extract_anthropic_blocks():
    body = json.dumps({"messages": [
        {"role": "user", "content": [{"type": "text", "text": "card 4111 1111 1111 1111"}]}
    ]})
    assert "4111 1111 1111 1111" in addon.extract_prompt(body)


def test_extract_gemini():
    body = json.dumps({"contents": [{"parts": [{"text": "hello gemini"}]}]})
    assert "hello gemini" in addon.extract_prompt(body)


def test_extract_legacy_and_nonjson():
    assert "hi there" in addon.extract_prompt(json.dumps({"prompt": "hi there"}))
    assert addon.extract_prompt("not json at all") == "not json at all"
    assert addon.extract_prompt(b"") == ""


def test_should_block():
    assert addon.should_block({"action": "block"}, enforce=True)
    assert not addon.should_block({"action": "block"}, enforce=False)
    assert not addon.should_block({"action": "warn"}, enforce=True)
    assert not addon.should_block({"action": "allow"}, enforce=True)
