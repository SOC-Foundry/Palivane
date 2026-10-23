"""Parse-miss reporting in the Codex, Gemini and Copilot hooks (Cursor's is in
test_palivane_cursor_hook.py).

The report exists so a fail-open client cannot go blind in silence: a prompt event that arrives
with no `prompt` field means the vendor's contract moved, the hook still fires and still exits 0,
and the heartbeat stays green while every prompt goes unscanned. Each of these hooks read `cfg`
two lines before assigning it, so every report raised UnboundLocalError, which the script's
fail-open handler swallowed: the hook looked healthy and the counter never moved."""

from __future__ import annotations

import importlib.util
import io
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_CLI = Path(__file__).resolve().parents[2] / "cli"


def _load(name: str, script: str):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / script)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


codex = _load("pv_codex_parse_miss", "palivane-codex-hook")
gemini = _load("pv_gemini_parse_miss", "palivane-gemini-hook")
copilot = _load("pv_copilot_parse_miss", "palivane-copilot-hook")

# (module, the event that carries a prompt, the tool name the report must carry)
PROMPT_HOOKS = {
    "codex": (codex, {"hook_event_name": "UserPromptSubmit"}, "codex-cli"),
    "gemini": (gemini, {"hook_event_name": "BeforeAgent"}, "gemini-cli"),
}


def _drive(hook, monkeypatch, capsys, event, connected=True):
    """Run main() against a stubbed backend, recording every `_post` it makes."""
    calls, reads = [], []
    cfg = {"url": "https://palivane.example" if connected else "",
           "token": "ak_test" if connected else "", "enforce": False, "timeout": 5.0,
           "user": "dev@acme.com", "exclude": []}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(hook, "read_config", lambda: reads.append(1) or cfg)
    monkeypatch.setattr(hook, "_post",
                        lambda endpoint, payload, c, **kw: calls.append((endpoint, payload, c, kw))
                        or {"action": "allow"})
    monkeypatch.setattr(hook, "_send_detached", lambda *a, **k: calls.append(("detached",)))
    rc = hook.main()
    return rc, capsys.readouterr().out.strip(), calls, reads


@pytest.mark.parametrize("which", sorted(PROMPT_HOOKS))
def test_a_prompt_event_with_no_prompt_field_reports_a_parse_miss(which, monkeypatch, capsys):
    hook, base, tool = PROMPT_HOOKS[which]
    rc, out, calls, _ = _drive(hook, monkeypatch, capsys, {**base, "cwd": "/work", "version": "1.2.3"})
    assert rc == 0 and out == ""                      # nothing for the host to act on, and no crash
    assert len(calls) == 1
    endpoint, payload, cfg, kw = calls[0]
    assert endpoint == "/api/ingest/ai-usage"
    assert payload["parse_miss"] is True and payload["tool"] == tool
    assert f"({tool}/1.2.3)" in kw["ua"]              # which host build was live: the whole point
    assert cfg["timeout"] <= 3.0                      # cheap: it must never slow a prompt down


@pytest.mark.parametrize("which", sorted(PROMPT_HOOKS))
def test_the_parse_miss_report_goes_nowhere_when_not_connected(which, monkeypatch, capsys):
    hook, base, _ = PROMPT_HOOKS[which]
    rc, out, calls, _ = _drive(hook, monkeypatch, capsys, {**base, "cwd": "/work"}, connected=False)
    assert rc == 0 and out == "" and calls == []


@pytest.mark.parametrize("which", sorted(PROMPT_HOOKS))
def test_an_empty_prompt_is_silence_not_drift(which, monkeypatch, capsys):
    hook, base, _ = PROMPT_HOOKS[which]
    rc, out, calls, _ = _drive(hook, monkeypatch, capsys, {**base, "prompt": "", "cwd": "/work"})
    assert rc == 0 and calls == []


@pytest.mark.parametrize("which", sorted(PROMPT_HOOKS))
def test_a_normal_prompt_is_scanned_not_reported_as_a_parse_miss(which, monkeypatch, capsys):
    hook, base, _ = PROMPT_HOOKS[which]
    rc, out, calls, _ = _drive(hook, monkeypatch, capsys, {**base, "prompt": "refactor this", "cwd": "/work"})
    assert rc == 0 and len(calls) == 1
    assert calls[0][0] == "/api/ingest/ai-usage" and "parse_miss" not in calls[0][1]


@pytest.mark.parametrize("which", sorted(PROMPT_HOOKS))
def test_the_config_is_read_once_per_event(which, monkeypatch, capsys):
    hook, base, _ = PROMPT_HOOKS[which]
    _, _, _, reads = _drive(hook, monkeypatch, capsys, {**base, "prompt": "hi", "cwd": "/work"})
    assert len(reads) == 1


# --- Copilot dispatches on the SHAPE of the event (it has no event-name field). A missing
# `prompt` key is some other event and stays silent; a `prompt` key that is present but not a
# string is a prompt event whose shape moved, and is reported. main() used to return before the
# report for that case, so the counter could never move for Copilot (#281).

@pytest.mark.parametrize("prompt", [None, 42, ["refactor this"], {"text": "refactor this"}])
def test_copilot_reports_a_present_non_string_prompt_through_main(prompt, monkeypatch, capsys):
    rc, out, calls, reads = _drive(copilot, monkeypatch, capsys,
                                   {"prompt": prompt, "cwd": "/work", "version": "9.8.7"})
    assert rc == 0 and out == "" and len(reads) == 1            # never a deny: exit 0, silent
    assert len(calls) == 1
    endpoint, payload, cfg, kw = calls[0]
    assert endpoint == "/api/ingest/ai-usage" and payload["parse_miss"] is True
    assert payload["tool"] == "copilot" and "(copilot/9.8.7)" in kw["ua"]
    assert cfg["timeout"] <= 3.0


def test_copilot_event_without_a_prompt_key_is_not_a_parse_miss(monkeypatch, capsys):
    rc, out, calls, _ = _drive(copilot, monkeypatch, capsys, {"cwd": "/work", "sessionId": "s"})
    assert rc == 0 and out == "" and calls == []


def test_copilot_parse_miss_is_not_reported_when_not_connected(monkeypatch, capsys):
    rc, out, calls, _ = _drive(copilot, monkeypatch, capsys, {"prompt": 7, "cwd": "/work"},
                               connected=False)
    assert rc == 0 and out == "" and calls == []


def test_copilots_report_carries_its_tool_and_the_host_build():
    posts = []
    cfg = {"url": "https://palivane.example", "token": "ak_test", "timeout": 5.0, "user": "d@a.com"}
    orig = copilot._post
    copilot._post = lambda endpoint, payload, c, **kw: posts.append((endpoint, payload, c, kw)) or {}
    try:
        copilot.report_parse_miss({"version": "9.8.7"}, cfg)
        copilot.report_parse_miss({}, {**cfg, "url": ""})            # not connected: nothing
    finally:
        copilot._post = orig
    assert len(posts) == 1
    endpoint, payload, c, kw = posts[0]
    assert endpoint == "/api/ingest/ai-usage" and payload["parse_miss"] is True
    assert payload["tool"] == "copilot" and "(copilot/9.8.7)" in kw["ua"] and c["timeout"] <= 3.0


def test_copilot_main_survives_an_empty_prompt_and_a_normal_one(monkeypatch, capsys):
    rc, out, calls, reads = _drive(copilot, monkeypatch, capsys, {"prompt": "", "cwd": "/work"})
    assert rc == 0 and out == "" and calls == []                      # silence, and no crash
    rc, out, calls, reads = _drive(copilot, monkeypatch, capsys, {"prompt": "refactor this", "cwd": "/work"})
    assert rc == 0 and out == "" and calls == [("detached",)] and len(reads) == 1
