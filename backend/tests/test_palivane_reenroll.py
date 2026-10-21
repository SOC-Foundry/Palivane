"""cli/palivane-reenroll: --setup takes the enrollment token off argv, and secrets land 0600."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

# The script has no .py extension, so the source loader is named explicitly.
_path = Path(__file__).resolve().parents[2] / "cli" / "palivane-reenroll"
_spec = importlib.util.spec_from_loader("palivane_reenroll", SourceFileLoader("palivane_reenroll", str(_path)))
reenroll = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reenroll)


@pytest.fixture
def home(tmp_path, monkeypatch):
    cfg = tmp_path / "palivane" / "enroll.json"
    monkeypatch.setattr(reenroll, "_USER_CFG", str(cfg))
    monkeypatch.setattr(reenroll, "_KEY_CACHE", str(tmp_path / "palivane" / "device-key"))
    monkeypatch.delenv("PALIVANE_ENROLL_TOKEN", raising=False)
    return cfg


def _setup(monkeypatch, argv, stdin=""):
    monkeypatch.setattr(sys, "argv", ["palivane-reenroll", "--setup", *argv])
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    reenroll.main()


def _written(cfg):
    return json.loads(cfg.read_text())


def test_setup_reads_token_from_env(home, monkeypatch):
    monkeypatch.setenv("PALIVANE_ENROLL_TOKEN", "et_from_env")
    _setup(monkeypatch, ["https://p.example/"])
    assert _written(home)["enroll_token"] == "et_from_env"
    assert _written(home)["url"] == "https://p.example"


def test_setup_reads_token_from_stdin(home, monkeypatch):
    _setup(monkeypatch, ["https://p.example", "-"], stdin="et_from_stdin\n")
    assert _written(home)["enroll_token"] == "et_from_stdin"
    _setup(monkeypatch, ["https://p.example"], stdin="et_again\n")   # token argument omitted
    assert _written(home)["enroll_token"] == "et_again"


def test_setup_argv_token_still_works(home, monkeypatch):
    _setup(monkeypatch, ["https://p.example", "et_legacy"])
    assert _written(home)["enroll_token"] == "et_legacy"


def test_setup_without_token_fails(home, monkeypatch):
    with pytest.raises(SystemExit):
        _setup(monkeypatch, ["https://p.example"], stdin="")
    assert not home.exists()


def test_secret_files_are_private(home, monkeypatch):
    monkeypatch.setenv("PALIVANE_ENROLL_TOKEN", "et_x")
    _setup(monkeypatch, ["https://p.example"])
    reenroll._write_cached_key("ak_device")
    for p in (home, Path(reenroll._KEY_CACHE)):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(home.parent).st_mode) == 0o700
