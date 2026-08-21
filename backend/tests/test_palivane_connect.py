"""Self-serve onboarding (cli/palivane-connect): settings writing + idempotent hook merge."""

from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

_path = Path(__file__).resolve().parents[2] / "cli" / "palivane-connect"
_spec = importlib.util.spec_from_loader("palivane_connect", SourceFileLoader("palivane_connect", str(_path)))
wc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wc)


def test_merge_hook_adds_then_skips_duplicate():
    data: dict = {}
    assert wc._merge_hook(data, "PreToolUse", "/opt/palivane/palivane-hook", timeout=10) is True
    entry = data["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == "*"
    assert entry["hooks"][0] == {"type": "command", "command": "/opt/palivane/palivane-hook", "timeout": 10}
    # Re-run (even from a different install path) is a no-op.
    assert wc._merge_hook(data, "PreToolUse", "/usr/local/bin/palivane-hook", timeout=10) is False
    assert len(data["hooks"]["PreToolUse"]) == 1


def test_merge_hook_preserves_existing_foreign_hooks():
    data = {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]}}
    assert wc._merge_hook(data, "PreToolUse", "/opt/palivane-hook", timeout=10) is True
    assert len(data["hooks"]["PreToolUse"]) == 2
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "my-linter"


def test_write_claude_code_env_and_hooks(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    path, installed = wc._write_claude_code("ak_tok123", "https://w.corp.io", "dev@acme.com",
                                            route_gateway=True)

    data = json.load(open(path))
    env = data["env"]
    assert env["ANTHROPIC_BASE_URL"] == "https://w.corp.io"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "ak_tok123"
    assert env["PALIVANE_URL"] == "https://w.corp.io"
    assert env["PALIVANE_TOKEN"] == "ak_tok123"
    events = {e for e in data["hooks"]}
    assert events == {"PreToolUse", "UserPromptSubmit", "SessionStart"}
    # The prompt hook runs the same script as the tool-call hook.
    assert data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] == "/opt/palivane/palivane-hook"
    assert "--async --quiet" in data["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert len(installed) == 3
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    # Second run: same env, no duplicated hooks.
    wc._write_claude_code("ak_tok123", "https://w.corp.io", "dev@acme.com", route_gateway=True)
    data = json.load(open(path))
    assert len(data["hooks"]["PreToolUse"]) == 1
    assert len(data["hooks"]["UserPromptSubmit"]) == 1
    assert len(data["hooks"]["SessionStart"]) == 1


def test_default_keeps_claude_codes_own_auth(monkeypatch, tmp_path):
    """Gateway routing is opt-in: the default write never touches ANTHROPIC_*."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    path, _ = wc._write_claude_code("ak_tok", "https://w.corp.io", "dev@acme.com")
    env = json.load(open(path))["env"]
    assert "ANTHROPIC_BASE_URL" not in env and "ANTHROPIC_AUTH_TOKEN" not in env
    assert env["PALIVANE_URL"] == "https://w.corp.io" and env["PALIVANE_TOKEN"] == "ak_tok"


def test_rerun_without_gateway_cleans_previous_routing(monkeypatch, tmp_path):
    """Re-running connect (no flag) remediates installs a previous version gateway-routed."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    path, _ = wc._write_claude_code("ak_old", "https://w.corp.io", "dev@acme.com",
                                    route_gateway=True)
    path, installed = wc._write_claude_code("ak_new", "https://w.corp.io/", "dev@acme.com")
    env = json.load(open(path))["env"]
    assert "ANTHROPIC_BASE_URL" not in env and "ANTHROPIC_AUTH_TOKEN" not in env
    assert env["PALIVANE_TOKEN"] == "ak_new"
    assert any("removed gateway routing" in i for i in installed)


def test_rerun_leaves_foreign_base_url_alone(monkeypatch, tmp_path):
    """A user's own custom ANTHROPIC_BASE_URL (not our gateway) is never removed."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    home = tmp_path / ".claude"
    home.mkdir()
    (home / "settings.json").write_text(json.dumps(
        {"env": {"ANTHROPIC_BASE_URL": "https://my-own-proxy.example",
                 "ANTHROPIC_AUTH_TOKEN": "sk-mine"}}))
    path, installed = wc._write_claude_code("ak_tok", "https://w.corp.io", "dev@acme.com")
    env = json.load(open(path))["env"]
    assert env["ANTHROPIC_BASE_URL"] == "https://my-own-proxy.example"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-mine"
    assert not any("removed gateway routing" in i for i in installed)


def test_write_claude_code_missing_scripts_noted(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    path, installed = wc._write_claude_code("ak_t", "https://w.io", "")
    data = json.load(open(path))
    assert "hooks" not in data or not data["hooks"]
    assert any("palivane-hook not found" in i for i in installed)
    assert any("palivane-posture not found" in i for i in installed)


# --- Cursor wiring ---------------------------------------------------------------------

def test_merge_cursor_hook_flat_shape_and_idempotent():
    data: dict = {}
    assert wc._merge_cursor_hook(data, "beforeSubmitPrompt", "/opt/palivane/palivane-cursor-hook") is True
    assert data["hooks"]["beforeSubmitPrompt"][0] == {"command": "/opt/palivane/palivane-cursor-hook"}
    # Re-run from a different path is a no-op (same script basename).
    assert wc._merge_cursor_hook(data, "beforeSubmitPrompt", "/usr/local/bin/palivane-cursor-hook") is False
    assert len(data["hooks"]["beforeSubmitPrompt"]) == 1


def test_write_cursor_installs_hooks_and_creds(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".cursor").mkdir()                      # Cursor "installed"
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, items = wc._write_cursor("ak_tok", "https://w.corp.io", "dev@acme.com")

    hooks = json.load(open(hpath))
    assert hooks["version"] == 1
    assert set(hooks["hooks"]) == set(wc._CURSOR_EVENTS)
    for ev in wc._CURSOR_EVENTS:
        assert hooks["hooks"][ev][0]["command"] == "/opt/palivane/palivane-cursor-hook"
    # Creds file the hook reads (Cursor doesn't pass env to hooks).
    creds = json.load(open(tmp_path / ".cursor" / "palivane.json"))
    assert creds == {"url": "https://w.corp.io", "token": "ak_tok", "user": "dev@acme.com"}
    assert oct(os.stat(tmp_path / ".cursor" / "palivane.json").st_mode & 0o777) == "0o600"
    assert any("installed" in i for i in items)

    # Second run: idempotent.
    wc._write_cursor("ak_tok", "https://w.corp.io", "dev@acme.com")
    hooks = json.load(open(hpath))
    assert len(hooks["hooks"]["beforeSubmitPrompt"]) == 1


def test_write_cursor_skipped_when_cursor_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))            # no ~/.cursor dir
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, items = wc._write_cursor("ak_tok", "https://w.io", "")
    assert hpath is None
    assert any("Cursor not detected" in i for i in items)
    assert not (tmp_path / ".cursor").exists()           # nothing created


def test_write_cursor_none_when_hook_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".cursor").mkdir()
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    assert wc._write_cursor("ak_tok", "https://w.io", "") is None


# --- Gemini CLI wiring -------------------------------------------------------------------

def test_write_gemini_installs_hooks_and_creds(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".gemini").mkdir()                      # Gemini CLI "installed"
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    spath, items = wc._write_gemini("ak_tok", "https://w.corp.io", "dev@acme.com")

    settings = json.load(open(spath))
    assert set(settings["hooks"]) == {"BeforeAgent", "BeforeTool"}
    ba = settings["hooks"]["BeforeAgent"][0]
    assert "matcher" not in ba                          # BeforeAgent takes no matcher
    assert ba["hooks"][0]["command"] == "/opt/palivane/palivane-gemini-hook"
    assert ba["hooks"][0]["timeout"] == 10000           # Gemini timeouts are milliseconds
    assert settings["hooks"]["BeforeTool"][0]["matcher"] == ".*"
    creds = json.load(open(tmp_path / ".gemini" / "palivane.json"))
    assert creds == {"url": "https://w.corp.io", "token": "ak_tok", "user": "dev@acme.com"}
    assert oct(os.stat(tmp_path / ".gemini" / "palivane.json").st_mode & 0o777) == "0o600"
    assert any("installed" in i for i in items)

    # Second run: idempotent, and existing foreign settings survive.
    wc._write_gemini("ak_tok", "https://w.corp.io", "dev@acme.com")
    settings = json.load(open(spath))
    assert len(settings["hooks"]["BeforeAgent"]) == 1
    assert len(settings["hooks"]["BeforeTool"]) == 1


def test_write_gemini_preserves_existing_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    d = tmp_path / ".gemini"
    d.mkdir()
    (d / "settings.json").write_text(json.dumps(
        {"theme": "dark", "hooks": {"BeforeTool": [
            {"matcher": "write_file", "hooks": [{"name": "lint", "type": "command",
                                                 "command": "my-linter"}]}]}}))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    spath, _ = wc._write_gemini("ak_tok", "https://w.io", "")
    settings = json.load(open(spath))
    assert settings["theme"] == "dark"
    assert len(settings["hooks"]["BeforeTool"]) == 2
    assert settings["hooks"]["BeforeTool"][0]["hooks"][0]["command"] == "my-linter"


def test_write_gemini_skipped_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))            # no ~/.gemini dir
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    spath, items = wc._write_gemini("ak_tok", "https://w.io", "")
    assert spath is None
    assert any("Gemini CLI not detected" in i for i in items)
    assert not (tmp_path / ".gemini").exists()           # nothing created


def test_write_gemini_none_when_hook_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".gemini").mkdir()
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    assert wc._write_gemini("ak_tok", "https://w.io", "") is None


# --- Codex CLI wiring --------------------------------------------------------------------

def test_write_codex_installs_hooks_and_creds(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".codex").mkdir()                        # Codex CLI "installed"
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, items = wc._write_codex("ak_tok", "https://w.corp.io", "dev@acme.com")

    hooks = json.load(open(hpath))
    assert set(hooks["hooks"]) == {"UserPromptSubmit", "PreToolUse"}
    ups = hooks["hooks"]["UserPromptSubmit"][0]
    assert "matcher" not in ups                          # UserPromptSubmit takes no matcher
    assert ups["hooks"][0] == {"type": "command",
                               "command": "/opt/palivane/palivane-codex-hook", "timeout": 10}
    assert hooks["hooks"]["PreToolUse"][0]["matcher"] == ".*"
    creds = json.load(open(tmp_path / ".codex" / "palivane.json"))
    assert creds == {"url": "https://w.corp.io", "token": "ak_tok", "user": "dev@acme.com"}
    assert any("installed" in i for i in items)
    assert any("/hooks" in i for i in items)             # one-time trust approval noted

    # Second run: idempotent.
    wc._write_codex("ak_tok", "https://w.corp.io", "dev@acme.com")
    hooks = json.load(open(hpath))
    assert len(hooks["hooks"]["UserPromptSubmit"]) == 1
    assert len(hooks["hooks"]["PreToolUse"]) == 1


def test_write_codex_skipped_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))            # no ~/.codex dir
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, items = wc._write_codex("ak_tok", "https://w.io", "")
    assert hpath is None
    assert any("Codex CLI not detected" in i for i in items)


def test_write_codex_none_when_hook_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".codex").mkdir()
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    assert wc._write_codex("ak_tok", "https://w.io", "") is None


def test_write_copilot_installs_hooks_and_creds(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".copilot").mkdir()                      # Copilot CLI "installed"
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, items = wc._write_copilot("ak_tok", "https://w.corp.io", "dev@acme.com")

    hooks = json.load(open(hpath))
    assert hooks["version"] == 1                         # Copilot's schema requires it
    assert set(hooks["hooks"]) == {"preToolUse", "userPromptSubmitted"}
    entry = hooks["hooks"]["preToolUse"][0]
    # Copilot's entry shape: a bash command string + timeoutSec (not command/timeout).
    assert entry == {"type": "command", "bash": "/opt/palivane/palivane-copilot-hook",
                     "timeoutSec": 10}
    creds = json.load(open(tmp_path / ".copilot" / "palivane.json"))
    assert creds == {"url": "https://w.corp.io", "token": "ak_tok", "user": "dev@acme.com"}
    assert any("installed" in i for i in items)

    # Second run: idempotent — same content, reported as already present.
    hpath2, items2 = wc._write_copilot("ak_tok", "https://w.corp.io", "dev@acme.com")
    assert hpath2 == hpath
    assert any("already present" in i for i in items2)


def test_write_copilot_owns_its_file_only(monkeypatch, tmp_path):
    # A user hook file in ~/.copilot/hooks/ is never touched — Palivane owns palivane.json.
    monkeypatch.setenv("HOME", str(tmp_path))
    hooks_dir = tmp_path / ".copilot" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "mine.json").write_text(json.dumps(
        {"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "my-guard"}]}}))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, _ = wc._write_copilot("ak_tok", "https://w.corp.io", "dev@acme.com")
    assert hpath.endswith("palivane.json")
    mine = json.load(open(hooks_dir / "mine.json"))
    assert mine["hooks"]["preToolUse"][0]["bash"] == "my-guard"


def test_write_copilot_skipped_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))            # no ~/.copilot dir
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    hpath, items = wc._write_copilot("ak_tok", "https://w.io", "")
    assert hpath is None
    assert any("Copilot CLI not detected" in i for i in items)


def test_write_copilot_none_when_hook_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".copilot").mkdir()
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    assert wc._write_copilot("ak_tok", "https://w.io", "") is None


def test_uninstall_removes_copilot_files(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    hooks_dir = tmp_path / ".copilot" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "palivane.json").write_text("{}")
    (hooks_dir / "mine.json").write_text("{}")           # user's own hook file survives
    (tmp_path / ".copilot" / "palivane.json").write_text("{}")
    out = wc._uninstall()
    assert not (hooks_dir / "palivane.json").exists()
    assert not (tmp_path / ".copilot" / "palivane.json").exists()
    assert (hooks_dir / "mine.json").exists()
    assert any("Copilot" in i for i in out)


def test_upstream_warning_only_when_console_says_no_key():
    console = "https://w.corp.io"
    # Console reported no forwarding upstream: warn, pointing at Settings.
    warning = wc._upstream_warning({"upstream": "0"}, console)
    assert warning and "Gateway upstreams" in warning and console in warning
    # Key present, or an older console that doesn't send the flag: stay quiet.
    assert wc._upstream_warning({"upstream": "1"}, console) is None
    assert wc._upstream_warning({}, console) is None


def test_no_upstream_skips_gateway_routing_keeps_local_planes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/palivane/{name}")
    path, installed = wc._write_claude_code("ak_tok", "https://w.io", "dev@a.com",
                                            route_gateway=False)
    env = json.load(open(path))["env"]
    # Claude Code keeps its own auth/billing — no gateway rerouting without an org key.
    assert "ANTHROPIC_BASE_URL" not in env and "ANTHROPIC_AUTH_TOKEN" not in env
    # Local capture planes still fully wired.
    assert env["PALIVANE_URL"] == "https://w.io" and env["PALIVANE_TOKEN"] == "ak_tok"
    assert len(installed) == 3


# --- plane self-update: `palivane connect` refreshes installed plane scripts -----------
def test_refresh_planes_updates_and_is_atomic(tmp_path, monkeypatch):
    """A re-connect fetches current plane scripts into ~/.palivane/bin (atomic, executable),
    so new plane code (e.g. the auth circuit breaker) lands without a full reinstall."""
    fetched = []

    class _R:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return self.body

    def fake_urlopen(req, timeout=None):
        fetched.append(req.full_url)
        return _R(b"#!/usr/bin/env python3\n# v2\n")

    monkeypatch.setattr(wc.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(wc, "_MANAGED_BIN", str(tmp_path / "bin"))
    monkeypatch.setattr(wc, "_in_repo_checkout", lambda: False)
    monkeypatch.setattr(wc.sys, "argv", ["palivane-connect"])
    # No proxy addon in this sandboxed HOME, so it isn't fetched.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    msgs = wc._refresh_planes("https://palivane.example")
    for name in wc._PLANE_SCRIPTS:
        p = tmp_path / "bin" / name
        assert p.exists() and os.access(p, os.X_OK)
        assert not (tmp_path / "bin" / (name + ".tmp")).exists()   # atomic: no temp left
    assert {u.rsplit("/", 1)[-1] for u in fetched} == set(wc._PLANE_SCRIPTS)
    assert any("updated" in m for m in msgs)


def test_refresh_planes_skips_checkout_and_flag(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(wc.urllib.request, "urlopen",
                        lambda *a, **k: calls.append(1))
    # Source checkout: sibling scripts are authoritative — don't fetch over them.
    monkeypatch.setattr(wc, "_in_repo_checkout", lambda: True)
    monkeypatch.setattr(wc.sys, "argv", ["palivane-connect"])
    assert any("checkout" in m for m in wc._refresh_planes("https://palivane.example"))
    # Explicit opt-out.
    monkeypatch.setattr(wc, "_in_repo_checkout", lambda: False)
    monkeypatch.setattr(wc.sys, "argv", ["palivane-connect", "--no-update"])
    assert wc._refresh_planes("https://palivane.example") == []
    assert calls == []   # never hit the network in either case


# --- --uninstall reverses what connect wrote (and only that) -------------------------
def test_uninstall_strips_only_palivane(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    claude = tmp_path / ".claude"; claude.mkdir()
    (claude / "settings.json").write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": "/x/palivane-hook"}]},
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]},
            ],
            "SessionStart": [{"matcher": "*", "hooks": [{"type": "command", "command": "palivane-posture --async"}]}],
        },
        "env": {"PALIVANE_TOKEN": "ak_x", "PALIVANE_URL": "https://w",
                "ANTHROPIC_AUTH_TOKEN": "ak_x", "ANTHROPIC_BASE_URL": "https://w", "EDITOR": "vim"},
    }))
    cur = tmp_path / ".cursor"; cur.mkdir()
    (cur / "hooks.json").write_text(json.dumps(
        {"version": 1, "hooks": {"beforeSubmitPrompt": [{"command": "palivane-cursor-hook"}, {"command": "keep"}]}}))
    (cur / "palivane.json").write_text("{}")

    msgs = wc._uninstall()

    d = json.loads((claude / "settings.json").read_text())
    assert d["hooks"]["PreToolUse"] == [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]
    assert "SessionStart" not in d["hooks"]              # emptied event pruned
    assert d["env"] == {"EDITOR": "vim"}                 # our env + our gateway routing gone
    c = json.loads((cur / "hooks.json").read_text())
    assert c["hooks"]["beforeSubmitPrompt"] == [{"command": "keep"}]
    assert not (cur / "palivane.json").exists()
    assert wc._uninstall() is not None                  # idempotent: second run is a no-op, no crash
    assert any("Claude Code" in m for m in msgs)


def test_uninstall_preserves_foreign_gateway_routing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    claude = tmp_path / ".claude"; claude.mkdir()
    (claude / "settings.json").write_text(json.dumps({"env": {
        "PALIVANE_TOKEN": "ak_x", "ANTHROPIC_AUTH_TOKEN": "sk-user", "ANTHROPIC_BASE_URL": "https://api.anthropic.com"}}))
    wc._uninstall()
    env = json.loads((claude / "settings.json").read_text())["env"]
    assert env == {"ANTHROPIC_AUTH_TOKEN": "sk-user", "ANTHROPIC_BASE_URL": "https://api.anthropic.com"}


# --- pre-rebrand (Palivane) scrub ----------------------------------------------------------




