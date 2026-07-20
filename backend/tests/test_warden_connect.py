"""Self-serve onboarding (cli/warden-connect): settings writing + idempotent hook merge."""

from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

_path = Path(__file__).resolve().parents[2] / "cli" / "warden-connect"
_spec = importlib.util.spec_from_loader("warden_connect", SourceFileLoader("warden_connect", str(_path)))
wc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wc)


def test_merge_hook_adds_then_skips_duplicate():
    data: dict = {}
    assert wc._merge_hook(data, "PreToolUse", "/opt/warden/warden-hook", timeout=10) is True
    entry = data["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == "*"
    assert entry["hooks"][0] == {"type": "command", "command": "/opt/warden/warden-hook", "timeout": 10}
    # Re-run (even from a different install path) is a no-op.
    assert wc._merge_hook(data, "PreToolUse", "/usr/local/bin/warden-hook", timeout=10) is False
    assert len(data["hooks"]["PreToolUse"]) == 1


def test_merge_hook_preserves_existing_foreign_hooks():
    data = {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]}}
    assert wc._merge_hook(data, "PreToolUse", "/opt/warden-hook", timeout=10) is True
    assert len(data["hooks"]["PreToolUse"]) == 2
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "my-linter"


def test_write_claude_code_env_and_hooks(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/warden/{name}")
    path, installed = wc._write_claude_code("ak_tok123", "https://w.corp.io", "dev@acme.com")

    data = json.load(open(path))
    env = data["env"]
    assert env["ANTHROPIC_BASE_URL"] == "https://w.corp.io"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "ak_tok123"
    assert env["WARDEN_URL"] == "https://w.corp.io"
    assert env["WARDEN_TOKEN"] == "ak_tok123"
    events = {e for e in data["hooks"]}
    assert events == {"PreToolUse", "SessionStart"}
    assert "--async --quiet" in data["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert len(installed) == 2
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    # Second run: same env, no duplicated hooks.
    wc._write_claude_code("ak_tok123", "https://w.corp.io", "dev@acme.com")
    data = json.load(open(path))
    assert len(data["hooks"]["PreToolUse"]) == 1
    assert len(data["hooks"]["SessionStart"]) == 1


def test_write_claude_code_missing_scripts_noted(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    path, installed = wc._write_claude_code("ak_t", "https://w.io", "")
    data = json.load(open(path))
    assert "hooks" not in data or not data["hooks"]
    assert any("warden-hook not found" in i for i in installed)
    assert any("warden-posture not found" in i for i in installed)


# --- Cursor wiring ---------------------------------------------------------------------

def test_merge_cursor_hook_flat_shape_and_idempotent():
    data: dict = {}
    assert wc._merge_cursor_hook(data, "beforeSubmitPrompt", "/opt/warden/warden-cursor-hook") is True
    assert data["hooks"]["beforeSubmitPrompt"][0] == {"command": "/opt/warden/warden-cursor-hook"}
    # Re-run from a different path is a no-op (same script basename).
    assert wc._merge_cursor_hook(data, "beforeSubmitPrompt", "/usr/local/bin/warden-cursor-hook") is False
    assert len(data["hooks"]["beforeSubmitPrompt"]) == 1


def test_write_cursor_installs_hooks_and_creds(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".cursor").mkdir()                      # Cursor "installed"
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/warden/{name}")
    hpath, items = wc._write_cursor("ak_tok", "https://w.corp.io", "dev@acme.com")

    hooks = json.load(open(hpath))
    assert hooks["version"] == 1
    assert set(hooks["hooks"]) == set(wc._CURSOR_EVENTS)
    for ev in wc._CURSOR_EVENTS:
        assert hooks["hooks"][ev][0]["command"] == "/opt/warden/warden-cursor-hook"
    # Creds file the hook reads (Cursor doesn't pass env to hooks).
    creds = json.load(open(tmp_path / ".cursor" / "warden.json"))
    assert creds == {"url": "https://w.corp.io", "token": "ak_tok", "user": "dev@acme.com"}
    assert oct(os.stat(tmp_path / ".cursor" / "warden.json").st_mode & 0o777) == "0o600"
    assert any("installed" in i for i in items)

    # Second run: idempotent.
    wc._write_cursor("ak_tok", "https://w.corp.io", "dev@acme.com")
    hooks = json.load(open(hpath))
    assert len(hooks["hooks"]["beforeSubmitPrompt"]) == 1


def test_write_cursor_skipped_when_cursor_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))            # no ~/.cursor dir
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/warden/{name}")
    hpath, items = wc._write_cursor("ak_tok", "https://w.io", "")
    assert hpath is None
    assert any("Cursor not detected" in i for i in items)
    assert not (tmp_path / ".cursor").exists()           # nothing created


def test_write_cursor_none_when_hook_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".cursor").mkdir()
    monkeypatch.setattr(wc, "_resolve_script", lambda name: None)
    assert wc._write_cursor("ak_tok", "https://w.io", "") is None


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
    monkeypatch.setattr(wc, "_resolve_script", lambda name: f"/opt/warden/{name}")
    path, installed = wc._write_claude_code("ak_tok", "https://w.io", "dev@a.com",
                                            route_gateway=False)
    env = json.load(open(path))["env"]
    # Claude Code keeps its own auth/billing — no gateway rerouting without an org key.
    assert "ANTHROPIC_BASE_URL" not in env and "ANTHROPIC_AUTH_TOKEN" not in env
    # Local capture planes still fully wired.
    assert env["WARDEN_URL"] == "https://w.io" and env["WARDEN_TOKEN"] == "ak_tok"
    assert len(installed) == 2
