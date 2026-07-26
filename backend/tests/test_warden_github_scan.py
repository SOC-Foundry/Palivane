"""GitHub scan plane (cli/warden-github-scan): repo enumeration, tree filtering, blob decode,
and the /api/scan/code payload shape. GitHub + backend I/O is monkeypatched — no network."""

from __future__ import annotations

import base64
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

# The script has no .py extension, so the source loader is named explicitly.
_path = Path(__file__).resolve().parents[2] / "cli" / "warden-github-scan"
_spec = importlib.util.spec_from_loader("warden_github_scan", SourceFileLoader("warden_github_scan", str(_path)))
ghs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ghs)


# --- canned GitHub API responses, keyed by the api-relative path ----------------------

def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


_ORG_REPOS = [
    {"name": "api", "owner": {"login": "acme"}, "default_branch": "main",
     "archived": False, "fork": False},
    {"name": "old", "owner": {"login": "acme"}, "default_branch": "main",
     "archived": True, "fork": False},     # archived — skipped
    {"name": "fork", "owner": {"login": "acme"}, "default_branch": "main",
     "archived": False, "fork": True},     # fork — skipped
]

_TREE = {"tree": [
    {"type": "blob", "path": "src/app.py", "size": 100, "sha": "sha-app"},
    {"type": "blob", "path": "big.py", "size": 5_000_000, "sha": "sha-big"},   # too large
    {"type": "blob", "path": "logo.png", "size": 50, "sha": "sha-png"},        # binary ext
    {"type": "tree", "path": "src", "size": 0, "sha": "sha-dir"},              # not a blob
]}

_BLOBS = {"sha-app": {"encoding": "base64", "content": _b64("SECRET = 'x'\n")}}


def _fake_gh_get(path, token, api):
    if path.startswith("/orgs/acme/repos"):
        return _ORG_REPOS
    if "/git/trees/" in path:
        return _TREE
    if "/git/blobs/" in path:
        return _BLOBS[path.rsplit("/", 1)[1]]
    raise AssertionError(f"unexpected GitHub path: {path}")


def _patch_gh(monkeypatch):
    monkeypatch.setattr(ghs, "_gh_get", _fake_gh_get)
    monkeypatch.setattr(ghs, "_gh_paged", lambda path, token, api: _fake_gh_get(path, token, api))


def _args(**kw):
    base = dict(org="acme", user=None, repo=None, branch=None,
                max_file_bytes=1_000_000, max_files=5000, include_archived=False)
    base.update(kw)
    return SimpleNamespace(**base)


# --- enumeration: archived + fork skipped ---------------------------------------------

def test_enumerate_org_skips_archived_and_forks(monkeypatch):
    _patch_gh(monkeypatch)
    repos = ghs.enumerate_repos(_args(), "gh", ghs.GITHUB_API)
    assert [r["name"] for r in repos] == ["api"]


def test_enumerate_org_include_archived(monkeypatch):
    _patch_gh(monkeypatch)
    repos = ghs.enumerate_repos(_args(include_archived=True), "gh", ghs.GITHUB_API)
    assert [r["name"] for r in repos] == ["api", "old", "fork"]


# --- tree filtering: oversized + binary paths dropped ---------------------------------

def test_repo_blobs_filters_oversized_and_binary(monkeypatch):
    _patch_gh(monkeypatch)
    repo = _ORG_REPOS[0]
    items = ghs.repo_blobs(repo, _args(), "gh", ghs.GITHUB_API)
    assert [i["path"] for i in items] == ["src/app.py"]   # big.py & logo.png & the tree gone
    assert items[0]["branch"] == "main" and items[0]["sha"] == "sha-app"


# --- blob fetch: base64 decode + owner/repo@branch:path label -------------------------

def test_fetch_blob_decodes_and_labels(monkeypatch):
    _patch_gh(monkeypatch)
    item = {"owner": "acme", "repo": "api", "branch": "main", "path": "src/app.py", "sha": "sha-app"}
    blob = ghs.fetch_blob(item, "gh", ghs.GITHUB_API)
    assert blob == {"path": "acme/api@main:src/app.py", "content": "SECRET = 'x'\n"}


def test_fetch_blob_skips_non_utf8(monkeypatch):
    monkeypatch.setattr(ghs, "_gh_get",
                        lambda p, t, a: {"encoding": "base64", "content": _b64_bytes(b"\xff\xfe")})
    item = {"owner": "acme", "repo": "api", "branch": "main", "path": "x.bin", "sha": "s"}
    assert ghs.fetch_blob(item, "gh", ghs.GITHUB_API) is None


def _b64_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode()


# --- POST payload shape to /api/scan/code ---------------------------------------------

def test_scan_batch_posts_expected_payload(monkeypatch):
    captured = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"action":"allow","scanned":1,"files":[]}'

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["token"] = req.headers.get("X-warden-token")
        captured["body"] = json.loads(req.data)
        return _Resp()

    monkeypatch.setattr(ghs.urllib.request, "urlopen", fake_urlopen)
    files = [{"path": "acme/api@main:src/app.py", "content": "SECRET = 'x'\n"}]
    result = ghs.scan_batch("http://localhost:8088/", "ak_tok", files, record=False)

    assert result["scanned"] == 1
    assert captured["url"] == "http://localhost:8088/api/scan/code"
    assert captured["token"] == "ak_tok"
    assert captured["body"] == {"files": files, "record": False}
