"""GitHub scan plane (cli/palivane-github-scan): repo enumeration, tree filtering, blob decode,
and the /api/scan/code payload shape. GitHub + backend I/O is monkeypatched — no network."""

from __future__ import annotations

import base64
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

# The script has no .py extension, so the source loader is named explicitly.
_path = Path(__file__).resolve().parents[2] / "cli" / "palivane-github-scan"
_spec = importlib.util.spec_from_loader("palivane_github_scan", SourceFileLoader("palivane_github_scan", str(_path)))
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


# --- blob scan: decode, detect LOCALLY, report findings only --------------------------
# The blob's text is read here and dropped here. What comes back is metadata: category,
# label, line, masked preview. Nothing that could reconstruct the file.

_ITEM = {"owner": "acme", "repo": "api", "branch": "main", "path": "src/app.py", "sha": "sha-app"}


def _blob(text: str):
    return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}


def test_scan_blob_returns_findings_not_content(monkeypatch):
    monkeypatch.setattr(ghs, "_gh_get",
                        lambda p, t, a: _blob("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"))
    hit = ghs.scan_blob(_ITEM, "gh", ghs.GITHUB_API)
    assert hit["path"] == "acme/api@main:src/app.py"
    assert "content" not in hit
    assert hit["findings"][0]["category"] == "secret_leak"
    assert hit["findings"][0]["line"] == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in str(hit), "the raw value must never leave the machine"


def test_scan_blob_returns_none_for_a_clean_file(monkeypatch):
    """A clean file is not reported at all — 'we looked and found nothing' needs no
    evidence sent anywhere, and it keeps an org sweep's request volume proportional to
    what was actually found rather than to how much source exists."""
    monkeypatch.setattr(ghs, "_gh_get", lambda p, t, a: _blob("def add(a, b):\n    return a + b\n"))
    assert ghs.scan_blob(_ITEM, "gh", ghs.GITHUB_API) is None


def test_scan_blob_finds_the_aws_secret_half(monkeypatch):
    monkeypatch.setattr(ghs, "_gh_get", lambda p, t, a: _blob(
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
    hit = ghs.scan_blob(_ITEM, "gh", ghs.GITHUB_API)
    assert hit and hit["findings"][0]["label"] == "AWS secret access key"


def test_scan_blob_marks_non_utf8_unreadable_not_clean(monkeypatch):
    """A binary blob and a clean source file both produce no finding, but only the second
    was actually scanned — the summary line counts them separately."""
    monkeypatch.setattr(ghs, "_gh_get",
                        lambda p, t, a: {"encoding": "base64", "content": _b64_bytes(b"\xff\xfe")})
    item = {"owner": "acme", "repo": "api", "branch": "main", "path": "x.bin", "sha": "s"}
    assert ghs.scan_blob(item, "gh", ghs.GITHUB_API) is ghs.UNREADABLE


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
        captured["token"] = req.headers.get("X-palivane-token")
        captured["body"] = json.loads(req.data)
        return _Resp()

    monkeypatch.setattr(ghs.urllib.request, "urlopen", fake_urlopen)
    files = [{"path": "acme/api@main:src/app.py",
              "findings": [{"category": "secret_leak", "label": "AWS access key id",
                            "line": 1, "masked": "AKIA••••MPLE"}]}]
    result = ghs.scan_batch("http://localhost:8088/", "ak_tok", files, record=False)

    assert result["scanned"] == 1
    assert captured["url"] == "http://localhost:8088/api/scan/code"
    assert captured["token"] == "ak_tok"
    assert captured["body"] == {"files": files, "record": False}
    # The wire format is the whole point of the change: findings, never file text.
    assert "content" not in json.dumps(captured["body"])
