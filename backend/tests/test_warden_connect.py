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
    assert env["ANTHROPIC_BASE_URL"] == "https://w.corp.io/v1"
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
