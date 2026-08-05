"""git capture plane (git/palivane_git_scan.py): --all mode enumerates every tracked file."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

# The script has no .py extension, so the source loader is named explicitly.
_path = Path(__file__).resolve().parents[2] / "git" / "palivane_git_scan.py"
_spec = importlib.util.spec_from_loader("palivane_git_scan", SourceFileLoader("palivane_git_scan", str(_path)))
gscan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gscan)


def test_all_mode_lists_tracked_files(monkeypatch):
    # --all sweeps the whole repo via `git ls-files -z`; the module splits on NUL.
    calls = {}

    def fake_git(*args):
        calls["args"] = args
        return "app/main.py\0README.md\0.env\0"

    monkeypatch.setattr(gscan, "_git", fake_git)
    paths = gscan._changed("all", "")
    assert calls["args"] == ("ls-files", "-z")           # whole-repo sweep, not a diff
    assert paths == ["app/main.py", "README.md", ".env"]  # NUL-split, empties dropped
