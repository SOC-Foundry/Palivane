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


def test_diff_modes_include_renames(monkeypatch):
    # A renamed file (R) can carry new content; dropping it let a secret ride a `git mv`.
    seen = []
    monkeypatch.setattr(gscan, "_git", lambda *a: seen.append(a) or "")
    gscan._changed("staged", "")
    gscan._changed("range", "origin/main..HEAD")
    assert len(seen) == 2 and all("--diff-filter=ACMR" in call for call in seen)


def test_non_utf8_is_decoded_not_skipped(tmp_path):
    f = tmp_path / "latin1.env"
    f.write_bytes(b"caf\xe9 AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n")
    content, problem = gscan._content(str(f), "range")
    assert problem is None
    assert "AKIAIOSFODNN7EXAMPLE" in content and "�" in content


def test_binary_is_skipped_quietly(tmp_path):
    f = tmp_path / "logo.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n\0\0\0IHDR")
    assert gscan._content(str(f), "range") == (None, None)


def test_oversized_file_is_truncated_with_a_problem(tmp_path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"KEY=AKIAIOSFODNN7EXAMPLE\n" + b"a" * (gscan.MAX_BYTES + 10))
    content, problem = gscan._content(str(f), "range")
    assert len(content) == gscan.MAX_BYTES and content.startswith("KEY=AKIA")
    assert problem and "only the first" in problem


def test_unreadable_file_reports_a_problem(tmp_path):
    content, problem = gscan._content(str(tmp_path / "gone.py"), "range")
    assert content is None and problem


def _run_main(monkeypatch, argv, response=None):
    import io
    import json
    import sys

    monkeypatch.setenv("PALIVANE_TOKEN", "ak_test")
    # --range makes explicit files read from the working tree (staged mode reads the index).
    monkeypatch.setattr(sys, "argv", ["palivane_git_scan.py", "--range", "HEAD", *argv])

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(gscan.urllib.request, "urlopen",
                        lambda req, timeout=0: _Resp(json.dumps(response or {"files": []}).encode()))
    return gscan.main()


def test_fail_closed_fails_on_unscannable_file(monkeypatch, tmp_path, capsys):
    ok = tmp_path / "ok.py"
    ok.write_text("x = 1\n")
    missing = str(tmp_path / "missing.py")
    assert _run_main(monkeypatch, [str(ok), missing]) == 0          # fail-open: warn only
    assert "WARNING" in capsys.readouterr().err
    assert _run_main(monkeypatch, ["--fail-closed", str(ok), missing]) == 1
    big = tmp_path / "big.txt"
    big.write_bytes(b"a" * (gscan.MAX_BYTES + 1))
    assert _run_main(monkeypatch, ["--fail-closed", str(big)]) == 1  # truncated scan is a gap
    assert _run_main(monkeypatch, ["--fail-closed", str(ok)]) == 0
