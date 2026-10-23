"""The server's enforce stance reaches tool calls, not only prompts (#278).

A tool call was scanned inline only when PALIVANE_ENFORCE was on locally. Otherwise a
detached child posted the report and nothing read the verdict, so a per-user enforce
override set in the console neither blocked nor asked. Prompts are scanned inline even in
monitor mode, and their verdict carries the actor's live `enforce`, so the hooks now
remember that bit (~/.palivane/enforce-<plane>.json, one-hour TTL) and scan tool calls
inline while it is on. Monitor-mode tool calls for everyone else stay detached.

Also: the ASK verdict in the hooks that gained it (Gemini, Copilot) and the one that cannot
carry it (Codex)."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_CLI = Path(__file__).resolve().parents[2] / "cli"


def _load(name: str, script: str):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / script)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


claude = _load("palivane_hook_srv_enforce", "palivane-hook")
cursor = _load("palivane_cursor_hook_srv_enforce", "palivane-cursor-hook")
codex = _load("palivane_codex_hook_srv_enforce", "palivane-codex-hook")
gemini = _load("palivane_gemini_hook_srv_enforce", "palivane-gemini-hook")
copilot = _load("palivane_copilot_hook_srv_enforce", "palivane-copilot-hook")

_CFG = {"url": "https://palivane.example", "token": "ak_test", "enforce": False,
        "timeout": 1.0, "user": "dev@acme.com", "exclude": []}

# Per hook: (module, a prompt event, a tool-call event, "was this output a deny?").
_PLANES = {
    "claude": (claude,
               {"hook_event_name": "UserPromptSubmit", "prompt": "please refactor", "cwd": "/w"},
               {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": "echo hi"}, "cwd": "/w"},
               lambda o: o["hookSpecificOutput"]["permissionDecision"] == "deny"),
    "cursor": (cursor,
               {"hook_event_name": "beforeSubmitPrompt", "prompt": "please refactor", "cwd": "/w"},
               {"hook_event_name": "beforeShellExecution", "command": "echo hi", "cwd": "/w"},
               lambda o: o.get("permission") == "deny"),
    "codex": (codex,
              {"hook_event_name": "UserPromptSubmit", "prompt": "please refactor", "cwd": "/w"},
              {"hook_event_name": "PreToolUse", "tool_name": "shell",
               "tool_input": {"command": "echo hi"}, "cwd": "/w"},
              lambda o: o["hookSpecificOutput"]["permissionDecision"] == "deny"),
    "gemini": (gemini,
               {"hook_event_name": "BeforeAgent", "prompt": "please refactor", "cwd": "/w"},
               {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
                "tool_input": {"command": "echo hi"}, "cwd": "/w"},
               lambda o: o.get("decision") == "deny"),
}

_BLOCK = {"action": "block", "risk_score": 90, "severity": "critical", "enforce": True,
          "signals": [{"category": "dangerous_command"}]}
_ALLOW_ENF = {"action": "allow", "risk_score": 0, "severity": "benign", "enforce": True}
_ALLOW_MON = {"action": "allow", "risk_score": 0, "severity": "benign", "enforce": False}
_ASKED = {"action": "warn", "ask": True, "enforce": True, "risk_score": 49,
          "severity": "suspicious", "signals": [{"category": "secret_leak"}],
          "remediation": ["Move it to an env var"]}


def _run(mod, monkeypatch, capsys, event, verdict, cfg=None):
    """Drive main() with a stubbed backend. Returns (rc, parsed stdout, inline posts,
    detached reports)."""
    inline, detached = [], []
    cfg = dict(cfg or _CFG)

    def post(*a, **k):
        inline.append(a)
        return dict(verdict)

    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(mod, "read_config", lambda: cfg)
    for fn in ("_post", "scan", "scan_mcp"):
        if hasattr(mod, fn):
            monkeypatch.setattr(mod, fn, post)
    monkeypatch.setattr(mod, "_send_detached", lambda *a, **k: detached.append(a))
    rc = mod.main()
    out = capsys.readouterr().out.strip()
    return rc, (json.loads(out) if out else None), inline, detached


def _claude_or_tool_out(name, out):
    # Cursor always answers a permission event; the rest stay silent on allow.
    return None if name == "cursor" and out == {"permission": "allow"} else out


# --- the cached bit: set by a prompt, honored by a tool call ---------------------------

@pytest.mark.parametrize("name", list(_PLANES))
def test_non_enforced_tool_call_stays_detached(name, monkeypatch, capsys):
    mod, _, tool, _ = _PLANES[name]
    rc, out, inline, detached = _run(mod, monkeypatch, capsys, tool, _BLOCK)
    assert rc == 0 and inline == [] and len(detached) == 1
    assert _claude_or_tool_out(name, out) is None            # nothing blocked, no waiting


@pytest.mark.parametrize("name", list(_PLANES))
def test_a_prompt_verdict_that_says_enforce_makes_tool_calls_inline_and_blocks(
        name, monkeypatch, capsys):
    mod, prompt, tool, denied = _PLANES[name]
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_ENF)       # the console enforces this actor
    assert mod.server_enforced(_CFG) is True
    rc, out, inline, detached = _run(mod, monkeypatch, capsys, tool, _BLOCK)
    assert rc == 0 and len(inline) == 1 and detached == []
    assert denied(out)


@pytest.mark.parametrize("name", list(_PLANES))
def test_cached_bit_lets_a_benign_call_through(name, monkeypatch, capsys):
    mod, prompt, tool, _ = _PLANES[name]
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_ENF)
    rc, out, inline, _ = _run(mod, monkeypatch, capsys, tool, _ALLOW_ENF)
    assert rc == 0 and len(inline) == 1 and _claude_or_tool_out(name, out) is None


@pytest.mark.parametrize("name", list(_PLANES))
def test_ttl_expiry_goes_back_to_detached(name, monkeypatch, capsys):
    mod, prompt, tool, _ = _PLANES[name]
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_ENF)
    later = mod.time.time() + mod._ENFORCE_TTL + 1
    monkeypatch.setattr(mod.time, "time", lambda: later)
    assert mod.server_enforced(_CFG) is False
    _, out, inline, detached = _run(mod, monkeypatch, capsys, tool, _BLOCK)
    assert inline == [] and len(detached) == 1 and _claude_or_tool_out(name, out) is None


@pytest.mark.parametrize("name", list(_PLANES))
def test_a_prompt_verdict_that_says_monitor_clears_the_bit_at_once(name, monkeypatch, capsys):
    mod, prompt, tool, _ = _PLANES[name]
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_ENF)
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_MON)      # the override was revoked
    assert mod.server_enforced(_CFG) is False
    _, _, inline, detached = _run(mod, monkeypatch, capsys, tool, _BLOCK)
    assert inline == [] and len(detached) == 1


@pytest.mark.parametrize("name", list(_PLANES))
def test_a_fail_open_verdict_changes_nothing(name, monkeypatch, capsys):
    mod, prompt, _, _ = _PLANES[name]
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_ENF)
    _run(mod, monkeypatch, capsys, prompt, {"action": "allow", "reason": "scan-failed"})
    assert mod.server_enforced(_CFG) is True                 # an outage is not a revocation
    os.unlink(mod._enforce_path())
    _run(mod, monkeypatch, capsys, prompt, {"action": "allow", "reason": "scan-failed"})
    assert mod.server_enforced(_CFG) is False                # nor an enforcement


@pytest.mark.parametrize("name", list(_PLANES))
def test_a_tool_verdict_refreshes_but_never_clears(name, monkeypatch, capsys):
    # A monitor override on ONE tool says nothing about the others, so only a prompt clears.
    mod, prompt, tool, _ = _PLANES[name]
    _run(mod, monkeypatch, capsys, prompt, _ALLOW_ENF)
    _run(mod, monkeypatch, capsys, tool, _ALLOW_MON)
    assert mod.server_enforced(_CFG) is True
    # ...and a tool verdict alone never turns a monitored device inline.
    os.unlink(mod._enforce_path())
    mod.remember_enforce(_ALLOW_MON, _CFG, authoritative=False)
    assert mod.server_enforced(_CFG) is False


@pytest.mark.parametrize("name", list(_PLANES))
def test_the_bit_belongs_to_one_backend_key_and_user(name):
    mod = _PLANES[name][0]
    mod.remember_enforce(_ALLOW_ENF, _CFG, authoritative=True)
    assert mod.server_enforced(_CFG) is True
    assert mod.server_enforced({**_CFG, "token": "ak_other"}) is False
    assert mod.server_enforced({**_CFG, "user": "someone@acme.com"}) is False
    assert mod.server_enforced({**_CFG, "url": "https://other.example"}) is False


@pytest.mark.parametrize("name", list(_PLANES))
def test_a_tampered_or_garbled_file_reads_as_monitor(name):
    mod = _PLANES[name][0]
    mod.remember_enforce(_ALLOW_ENF, _CFG, authoritative=True)
    path = mod._enforce_path()
    st = json.load(open(path))
    for until in (9e18, float("inf"), "soon", True, None):
        with open(path, "w") as fh:
            json.dump({**st, "until": until}, fh, allow_nan=True)
        assert mod.server_enforced(_CFG) is False, until
    with open(path, "w") as fh:
        fh.write("{not json")
    assert mod.server_enforced(_CFG) is False


@pytest.mark.parametrize("name", list(_PLANES))
def test_an_unwritable_state_dir_fails_open(name, monkeypatch, tmp_path):
    mod = _PLANES[name][0]
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(blocker))
    mod.remember_enforce(_ALLOW_ENF, _CFG, authoritative=True)   # must not raise
    assert mod.server_enforced(_CFG) is False


def test_each_plane_keeps_its_own_file():
    # The server resolves enforce per channel (claude-code, cursor, ...), so each hook keeps
    # its own reading.
    files = {_PLANES[n][0]._ENFORCE_FILE for n in _PLANES}
    assert len(files) == len(_PLANES)


def test_the_copies_have_not_drifted():
    """The helpers are copied into each standalone hook (they cannot import a shared module);
    keep the code identical. Docstrings may differ."""
    import ast
    import inspect

    def body(f):
        node = ast.parse(inspect.getsource(f)).body[0]
        if ast.get_docstring(node) is not None:
            node.body = node.body[1:]
        return ast.dump(node)

    every = [_PLANES[n][0] for n in _PLANES] + [copilot]
    for fn in ("remember_enforce", "server_enforced", "_enforce_path", "_enforce_key"):
        assert len({body(getattr(m, fn)) for m in every if hasattr(m, fn)}) == 1, fn
    for fn in ("should_block", "_ask_message"):
        assert len({body(getattr(m, fn)) for m in every if hasattr(m, fn)}) == 1, fn
    assert len({body(m.should_ask) for m in (claude, cursor, gemini)}) == 1


# --- the per-user override, end to end against the real backend ------------------------

def test_a_per_user_override_reaches_a_tool_call_end_to_end(client, raw_client, monkeypatch, capsys):
    client.post("/api/policies/overrides",
                json={"scope": "user", "match": "pilot@acme.com",
                      "disabled_checks": [], "enforce": "on"})
    key = client.post("/api/apikeys", json={"label": "hook", "actor": "pilot@acme.com"}).json()["token"]
    cfg = {**_CFG, "token": key, "user": ""}
    inline, detached = [], []

    def scan(endpoint, payload, url, token, user="", timeout=5.0, ua=""):
        inline.append(endpoint)
        r = raw_client.post(endpoint, json={**payload, "user": user},
                            headers={"X-Palivane-Token": token})
        assert r.status_code == 200, r.text
        return r.json()

    def drive(event):
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(claude, "read_config", lambda: cfg)
        monkeypatch.setattr(claude, "scan", scan)
        monkeypatch.setattr(claude, "scan_mcp",
                            lambda a, url, token, user="", timeout=5.0: scan("/api/ingest/mcp", a, url, token, user))
        monkeypatch.setattr(claude, "_send_detached", lambda *a, **k: detached.append(a))
        claude.main()
        out = capsys.readouterr().out.strip()
        return json.loads(out) if out else None

    rm = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
          "tool_input": {"command": "rm -rf /"}, "cwd": "/w"}
    assert drive(rm) is None and detached and not inline          # before any prompt: monitor
    detached.clear()
    drive({"hook_event_name": "UserPromptSubmit", "prompt": "tidy up the build dir", "cwd": "/w"})
    assert inline == ["/api/ingest/ai-usage"]
    out = drive(rm)
    assert inline[-1] == "/api/ingest/mcp" and not detached
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


# --- ASK where the host has one --------------------------------------------------------

def test_gemini_asks_on_a_tool_call_in_the_warn_band(monkeypatch, capsys):
    tool = _PLANES["gemini"][2]
    _, out, _, _ = _run(gemini, monkeypatch, capsys, tool, _ASKED, {**_CFG, "enforce": True})
    assert out["decision"] == "ask"
    assert "secret_leak" in out["systemMessage"] and "Move it to an env var" in out["systemMessage"]


def test_gemini_prompt_never_asks_and_block_wins(monkeypatch, capsys):
    prompt, tool = _PLANES["gemini"][1], _PLANES["gemini"][2]
    _, out, _, _ = _run(gemini, monkeypatch, capsys, prompt, _ASKED, {**_CFG, "enforce": True})
    assert out is None
    _, out, _, _ = _run(gemini, monkeypatch, capsys, tool, {**_ASKED, "action": "block"},
                        {**_CFG, "enforce": True})
    assert out["decision"] == "deny"


def test_codex_has_no_ask_so_a_warn_runs(monkeypatch, capsys):
    # Codex parses "ask" but does not support it (marks the hook failed, runs the call), so
    # the hook says nothing rather than turning the warn into a block.
    tool = _PLANES["codex"][2]
    rc, out, inline, _ = _run(codex, monkeypatch, capsys, tool, _ASKED, {**_CFG, "enforce": True})
    assert rc == 0 and len(inline) == 1 and out is None
    assert not hasattr(codex, "ask_output")


_COPILOT_TOOL = {"toolName": "bash", "toolArgs": json.dumps({"command": "echo hi"}), "cwd": "/w"}


def test_copilot_asks_on_a_tool_call_in_the_warn_band(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    _, out, _, _ = _run(copilot, monkeypatch, capsys, _COPILOT_TOOL, _ASKED)
    assert out["permissionDecision"] == "ask"
    assert "secret_leak" in out["permissionDecisionReason"]
    assert set(out) == {"permissionDecision", "permissionDecisionReason"}


def test_copilot_cloud_agent_runs_a_warn_instead_of_denying_it(monkeypatch, capsys):
    # The cloud agent treats ask as deny; a warn must not become a block there.
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    rc, out, _, _ = _run(copilot, monkeypatch, capsys, _COPILOT_TOOL, _ASKED)
    assert rc == 0 and out is None


def test_copilot_block_wins_over_ask_and_prompt_never_asks(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    _, out, _, _ = _run(copilot, monkeypatch, capsys, _COPILOT_TOOL, {**_ASKED, "action": "block"})
    assert out["permissionDecision"] == "deny"
    assert copilot.should_ask("userPromptSubmitted", _ASKED) is False
