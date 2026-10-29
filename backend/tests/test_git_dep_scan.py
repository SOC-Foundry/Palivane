"""The git hook vets changed dependency manifests, not just secrets.

The main page said commits AND dependencies are checked before they land, but nothing shipped
called /api/scan/deps. The hook now sends package.json / requirements*.txt to it too.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "palivane_git_scan", Path(__file__).resolve().parents[2] / "git" / "palivane_git_scan.py")
hook = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(hook)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PALIVANE_TOKEN", "ak_test")
    (tmp_path / "app.py").write_text("print('hi')\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0"}}\n')
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "requirements-dev.txt").write_text("requests==2.32.0\n")
    return tmp_path


def _run(monkeypatch, argv, replies):
    calls = []

    def fake_post(url, endpoint, token, body, fail_closed):
        calls.append((endpoint, [f["path"] for f in body["files"]]))
        return replies.get(endpoint, ({"files": [], "scanned": len(body["files"])}, None))
    monkeypatch.setattr(hook, "_post", fake_post)
    monkeypatch.setattr(sys, "argv", ["palivane_git_scan.py", *argv])
    return hook.main(), calls


def test_manifests_go_to_the_deps_scan_too(repo, monkeypatch):
    rc, calls = _run(monkeypatch, ["--all", "app.py", "package.json", "svc/requirements-dev.txt"], {})
    assert rc == 0
    assert calls[0] == ("/api/scan/code", ["app.py", "package.json", "svc/requirements-dev.txt"])
    assert calls[1] == ("/api/scan/deps", ["package.json", "svc/requirements-dev.txt"])


def test_no_manifest_no_deps_call(repo, monkeypatch):
    _, calls = _run(monkeypatch, ["--all", "app.py"], {})
    assert [c[0] for c in calls] == ["/api/scan/code"]


def test_no_deps_flag_skips_it(repo, monkeypatch):
    _, calls = _run(monkeypatch, ["--all", "--no-deps", "package.json"], {})
    assert [c[0] for c in calls] == ["/api/scan/code"]


def test_a_risky_dependency_blocks_the_commit(repo, monkeypatch, capsys):
    deps = {"files": [{"path": "package.json", "action": "block",
                       "signals": [{"category": "dependency_risk", "evidence": "postinstall"}]}]}
    rc, _ = _run(monkeypatch, ["--all", "package.json"], {"/api/scan/deps": (deps, None)})
    assert rc == 1
    out = capsys.readouterr()
    assert "package.json" in out.out and "dependency_risk" in out.out
    assert "risky" in out.err


def test_deps_backend_down_fails_open_by_default(repo, monkeypatch):
    rc, _ = _run(monkeypatch, ["--all", "package.json"], {"/api/scan/deps": (None, 0)})
    assert rc == 0


@pytest.mark.parametrize("path,hit", [
    ("package.json", True), ("web/package.json", True), ("requirements.txt", True),
    ("requirements-dev.txt", True), ("a/b/requirements.in.txt", True),
    ("package-lock.json", False), ("notpackage.json", False), ("requirements.md", False),
])
def test_manifest_names(path, hit):
    assert bool(hook._MANIFEST.search(path)) is hit
