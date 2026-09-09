"""Replay recorded host-agent payloads through the real extractors in cli/.

The point is drift. Every hook fails open, so when a vendor renames a field the hook keeps
firing, keeps returning 0, and the sensor heartbeat stays green while nothing is scanned —
the failure that looks exactly like a quiet week. These fixtures are the tripwire: a shape
change fails a test here rather than going unnoticed until someone audits coverage.

See fixtures/hook_payloads/README.md for how to capture a real payload. Fixtures still
marked hand-written are placeholders and are asserted to be a shrinking set, not a
permanent one.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_CLI = Path(__file__).resolve().parents[2] / "cli"
_FIXTURES = Path(__file__).parent / "fixtures" / "hook_payloads"

# Which script owns each agent, and what its prompt extractor is called.
_HOOKS = {
    "claude-code": ("palivane-hook", "build_prompt_usage"),
    "cursor": ("palivane-cursor-hook", "build_ai_usage"),
    "codex-cli": ("palivane-codex-hook", "build_ai_usage"),
    "gemini-cli": ("palivane-gemini-hook", "build_ai_usage"),
    "copilot": ("palivane-copilot-hook", "build_ai_usage"),
}


def _load(script: str):
    path = _CLI / script
    spec = importlib.util.spec_from_loader(script, SourceFileLoader(script, str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fixtures():
    return sorted(p for p in _FIXTURES.glob("*.json"))


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: p.stem)
def test_recorded_payload_still_extracts(path):
    fx = json.loads(path.read_text())
    script, extractor = _HOOKS[fx["agent"]]
    mod = _load(script)
    event = fx["event"]
    expect = fx["expect"]

    if expect["kind"] == "parse_miss":
        # The extractor must come back empty AND the hook must know that is drift rather
        # than an empty submission — reporting the difference is the whole mechanism.
        assert getattr(mod, extractor)(event) is None
        assert mod.prompt_parse_miss(event) is True
        return

    if expect["kind"] == "prompt":
        payload = getattr(mod, extractor)(event)
        assert payload is not None, (
            f"{path.name}: the prompt extractor returned nothing. Either this capture is "
            f"from a build whose shape we no longer read, or the extractor regressed.")
        assert expect["contains"] in payload["content"]
        # A real prompt must never be mistaken for drift.
        assert mod.prompt_parse_miss(event) is False


def test_every_agent_has_at_least_one_fixture():
    covered = {json.loads(p.read_text())["agent"] for p in _fixtures()}
    missing = set(_HOOKS) - covered
    assert not missing, f"no recorded payload for: {sorted(missing)}"


def test_hand_written_placeholders_are_declared():
    """Placeholders are allowed; silent ones are not.

    A hand-written fixture is written from the same assumption as the code it tests, so the
    two agree with each other forever and catch nothing. That is tolerable while real
    captures are pending, as long as each one says so out loud."""
    for p in _fixtures():
        fx = json.loads(p.read_text())
        assert fx.get("captured_from"), f"{p.name}: no captured_from"
        if "hand-written" in fx["captured_from"]:
            assert "REPLACE" in fx["captured_from"], (
                f"{p.name}: a hand-written fixture must say it needs replacing")
