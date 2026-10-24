"""The non-Claude hooks start palivane-posture themselves, so a machine without Claude Code
(whose SessionStart hook is the only other thing that runs posture) still self-updates."""

from __future__ import annotations

import importlib.util
import os
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_CLI = Path(__file__).resolve().parents[2] / "cli"
_HOOKS = ("palivane-cursor-hook", "palivane-codex-hook", "palivane-gemini-hook",
          "palivane-copilot-hook")
_CFG = {"url": "https://pal.example", "token": "ak_test"}


def _load(script: str):
    name = "kick_" + script.replace("-", "_")
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / script)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A home with the hook 'installed' in ~/.palivane/bin next to palivane-posture, and a
    Popen that records instead of spawning."""
    home = tmp_path / "home"
    bindir = home / ".palivane" / "bin"
    bindir.mkdir(parents=True)
    (bindir / "palivane-posture").write_text("#!/usr/bin/env python3\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PALIVANE_NO_SELF_UPDATE", raising=False)
    spawned = []

    def setup(script):
        mod = _load(script)
        mod.__file__ = str(bindir / script)
        monkeypatch.setattr(mod.subprocess, "Popen", lambda argv, **kw: spawned.append((argv, kw)))
        return mod

    return setup, spawned


@pytest.mark.parametrize("script", _HOOKS)
def test_an_installed_hook_starts_posture_with_its_own_credentials(script, installed):
    setup, spawned = installed
    mod = setup(script)
    mod.kick_posture(_CFG)
    assert len(spawned) == 1
    argv, kw = spawned[0]
    assert argv[1].endswith(os.path.join(".palivane", "bin", "palivane-posture"))
    assert kw["env"]["PALIVANE_URL"] == "https://pal.example"
    assert kw["env"]["PALIVANE_TOKEN"] == "ak_test"
    assert kw["start_new_session"] is True


@pytest.mark.parametrize("script", _HOOKS)
def test_it_starts_posture_at_most_every_few_hours(script, installed):
    setup, spawned = installed
    mod = setup(script)
    mod.kick_posture(_CFG)
    mod.kick_posture(_CFG)
    assert len(spawned) == 1
    stamp = Path(os.environ["PALIVANE_STATE_DIR"]) / "posture-kick"
    old = time.time() - mod._POSTURE_KICK_S - 60
    os.utime(stamp, (old, old))
    mod.kick_posture(_CFG)
    assert len(spawned) == 2


@pytest.mark.parametrize("script", _HOOKS)
def test_the_opt_out_and_a_copy_outside_palivane_bin_start_nothing(script, installed, monkeypatch):
    setup, spawned = installed
    mod = setup(script)
    monkeypatch.setenv("PALIVANE_NO_SELF_UPDATE", "1")
    mod.kick_posture(_CFG)
    monkeypatch.delenv("PALIVANE_NO_SELF_UPDATE")
    mod.__file__ = str(_CLI / script)          # a repo checkout / MDM copy: posture can't replace it
    mod.kick_posture(_CFG)
    assert spawned == []


@pytest.mark.parametrize("script", _HOOKS)
def test_no_posture_installed_starts_nothing(script, installed):
    setup, spawned = installed
    mod = setup(script)
    (Path(mod.__file__).parent / "palivane-posture").unlink()
    mod.kick_posture(_CFG)
    assert spawned == []
