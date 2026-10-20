"""GitHub secret scanning connector: what it reads, what it stores, and how it resumes."""

from __future__ import annotations

import base64
import json

import pytest

from app import github_secrets as gh
from app import saas_connectors as sc
from app.models import Finding

AWS = "AK" + "IA" + "4YTGH2NBQF7XZP3K"
GHP = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
TOKEN = "github_pat_" + "11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuv"


def _b64(text: str) -> dict:
    return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}


class FakeGitHub:
    """A tiny GitHub: two repositories, one private and one public, with a tree and two commits."""

    def __init__(self):
        self.calls: list[str] = []
        self.fail: dict[str, str] = {}                  # path prefix -> ConnectorError text
        self.pushed = "2026-10-01T00:00:00Z"
        self.repos = [
            {"full_name": "acme/app", "default_branch": "main", "private": True, "fork": False,
             "pushed_at": self.pushed},
            {"full_name": "acme/site", "default_branch": "main", "private": False, "fork": False,
             "pushed_at": self.pushed},
        ]
        self.blobs = {
            "b-config": f'DB = "x"\nAWS_KEY = "{AWS}"\n',
            "b-fixture": 'password = "hunter2hunter2"\n',
            "b-docs": 'set password = "hunter2hunter2" in your env\n',
            "b-clean": "print('hello')\n",
        }
        self.tree = [
            {"path": "src/config.py", "type": "blob", "sha": "b-config", "size": 40},
            {"path": "tests/fixture.py", "type": "blob", "sha": "b-fixture", "size": 30},
            {"path": "docs/guide.md", "type": "blob", "sha": "b-docs", "size": 30},
            {"path": "src/clean.py", "type": "blob", "sha": "b-clean", "size": 20},
            {"path": "assets/logo.png", "type": "blob", "sha": "b-png", "size": 20},
            {"path": "package-lock.json", "type": "blob", "sha": "b-lock", "size": 20},
        ]
        removed_then_added = (f"@@ -1,2 +1,3 @@\n context\n-OLD = \"{GHP}\"\n+NEW = \"{GHP}\"\n+x = 1\n")
        self.commit_files = {
            "c1": [{"filename": "deploy.sh", "status": "modified", "patch": removed_then_added}],
            "c2": [{"filename": "gone.env", "status": "removed", "patch": f"@@ -1 +0,0 @@\n-K={AWS}\n"}],
        }

    def __call__(self, url, **kw):
        path = url.replace("https://api.github.com", "")
        self.calls.append(path)
        for prefix, text in self.fail.items():
            if path.startswith(prefix):
                raise sc.ConnectorError(text)
        base = path.split("?")[0]
        if base == "/orgs/acme/repos":
            return self.repos if path.endswith("page=1") else []
        repo = "acme/app" if "/acme/app" in base else "acme/site"
        if base.endswith("/branches/main"):
            return {"commit": {"sha": "head-" + repo, "commit": {"tree": {"sha": "tree-" + repo}}}}
        if "/git/trees/" in base:
            return {"tree": self.tree if repo == "acme/app" else self.tree[:1], "truncated": False}
        if "/git/blobs/" in base:
            return _b64(self.blobs.get(base.rsplit("/", 1)[1], ""))
        if base.endswith("/commits"):
            if repo != "acme/app" or not path.endswith("page=1"):
                return []
            return [{"sha": s, "parents": [{}], "commit": {"author": {"date": d, "email": "dev@acme.com"}}}
                    for s, d in (("c2", "2026-10-02T00:00:00Z"), ("c1", "2026-10-01T00:00:00Z"))]
        if "/commits/" in base:
            sha = base.rsplit("/", 1)[1]
            return {"commit": {"author": {"email": "dev@acme.com"}}, "files": self.commit_files[sha]}
        raise AssertionError("unexpected GitHub call: " + path)


@pytest.fixture
def github(client, monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(sc, "_http_json", fake)
    r = client.post("/api/discovery/connectors", json={
        "platform": "github_secrets", "label": "acme",
        "credentials": {"token": TOKEN, "org": "acme", "history_days": 365}})
    assert r.status_code == 200, r.text
    fake.connector_id = r.json()["id"]
    return fake


def _sync(client, fake):
    r = client.post(f"/api/discovery/connectors/{fake.connector_id}/sync")
    assert r.status_code == 200, r.text
    return r.json()


def _findings(db_factory):
    db = db_factory()
    try:
        return [(f.subject, f.severity, f.risk_score, json.dumps(f.signals), f.content or "")
                for f in db.query(Finding).order_by(Finding.id)]
    finally:
        db.close()


def test_it_finds_secrets_in_files_and_in_added_diff_lines(client, github, db_factory):
    summary = _sync(client, github)
    assert summary["repos"] == 2 and summary["findings"] >= 3
    subjects = {s for s, *_ in _findings(db_factory)}
    assert "acme/app/src/config.py" in subjects          # in the tree
    assert "acme/app/deploy.sh" in subjects              # only in a commit's added line
    assert "acme/app/gone.env" not in subjects           # a removed line is not committed any more


def test_only_a_masked_preview_is_stored(client, github, db_factory):
    _sync(client, github)
    blob = (json.dumps(_findings(db_factory), ensure_ascii=False)
            + json.dumps(client.get("/api/findings").json(), ensure_ascii=False))
    assert AWS not in blob and GHP not in blob           # never the secret
    assert "AKIA••••ZP3K" in blob                        # the masked preview
    assert TOKEN not in blob                             # nor the connector's own credential
    assert "hunter2hunter2" not in blob


def test_a_finding_reads_as_a_repository_finding(client, github, db_factory):
    _sync(client, github)
    row = next(r for r in _findings(db_factory) if r[0] == "acme/app/src/config.py")
    sig = json.loads(row[3])[0]
    assert sig["title"].startswith("Credential in a repository")
    assert "src/config.py on line 2" in sig["detail"] and "git history" in sig["detail"]
    assert "device" not in sig["detail"]


def test_a_public_repository_scores_higher(client, github, db_factory):
    _sync(client, github)
    by = {s: r for s, _, r, *_ in _findings(db_factory)}
    assert by["acme/site/src/config.py"] > by["acme/app/src/config.py"]
    assert "PUBLIC" in next(json.loads(r[3])[0]["detail"] for r in _findings(db_factory)
                            if r[0] == "acme/site/src/config.py")


def test_generic_matches_in_fixtures_and_docs_are_dropped_but_vendor_keys_are_not(client, github, db_factory):
    github.blobs["b-fixture"] = f'password = "hunter2hunter2"\nreal = "{AWS}"\n'
    _sync(client, github)
    subjects = {s for s, *_ in _findings(db_factory)}
    assert "acme/app/tests/fixture.py" in subjects       # the AWS key fires wherever it is
    assert "acme/app/docs/guide.md" not in subjects      # a generic password in docs is illustrative
    sig = next(json.loads(r[3]) for r in _findings(db_factory) if r[0] == "acme/app/tests/fixture.py")
    assert all("hunter2" not in s["evidence"] for s in sig)


def test_binaries_and_lockfiles_cost_no_api_call(client, github):
    _sync(client, github)
    assert not any(c.endswith("/git/blobs/b-png") or c.endswith("/git/blobs/b-lock") for c in github.calls)


def test_nothing_pushed_means_nothing_read(client, github):
    _sync(client, github)
    first = len(github.calls)
    _sync(client, github)
    # the repository list is one call; each repository is skipped without touching it
    assert len(github.calls) - first == 1


def test_a_repeat_of_the_same_secret_folds_into_one_finding(client, github, db_factory):
    _sync(client, github)
    n = len(_findings(db_factory))
    github.repos[0]["pushed_at"] = "2026-10-03T00:00:00Z"        # pushed again: re-read, same secrets
    _sync(client, github)
    assert len(_findings(db_factory)) == n


def test_a_budget_stops_the_sync_and_the_next_one_resumes(client, github, db_factory, monkeypatch):
    monkeypatch.setattr(gh, "_BLOBS_PER_SYNC", 1)
    first = _sync(client, github)
    assert first.get("truncated") is True
    for _ in range(12):                                          # keep syncing until it has caught up
        if not _sync(client, github).get("truncated"):
            break
    subjects = {s for s, *_ in _findings(db_factory)}
    assert {"acme/app/src/config.py", "acme/site/src/config.py", "acme/app/deploy.sh"} <= subjects


def test_a_repository_the_token_cannot_read_does_not_stall_the_rest(client, github, db_factory):
    github.fail["/repos/acme/app/branches"] = "HTTP 403 from api.github.com: Resource not accessible"
    summary = _sync(client, github)
    assert summary["skipped"] >= 1 and not summary.get("truncated")
    assert "acme/site/src/config.py" in {s for s, *_ in _findings(db_factory)}


def test_a_rate_limit_stops_the_sync_cleanly(client, github):
    github.fail["/repos/acme/app/branches"] = "HTTP 403 from api.github.com: API rate limit exceeded"
    summary = _sync(client, github)
    assert summary["truncated"] is True


def test_a_missing_token_is_an_error_the_admin_sees(client, monkeypatch):
    monkeypatch.setattr(sc, "_http_json", FakeGitHub())
    cid = client.post("/api/discovery/connectors", json={
        "platform": "github_secrets", "label": "none", "credentials": {"org": "acme"}}).json()["id"]
    r = client.post(f"/api/discovery/connectors/{cid}/sync")
    assert r.status_code >= 400 and "token" in r.text.lower()


def test_include_and_exclude_choose_the_repositories(client, github, monkeypatch):
    client.post("/api/discovery/connectors", json={
        "platform": "github_secrets", "label": "acme",
        "credentials": {"token": TOKEN, "org": "acme", "exclude": "site", "history_days": 0}})
    summary = _sync(client, github)
    assert summary["repos"] == 1
    assert not any("/acme/site" in c for c in github.calls)


def test_the_locator_numbers_diff_lines_in_the_new_file():
    patch = "@@ -10,2 +20,3 @@\n keep\n-gone\n+" + f'K = "{AWS}"' + "\n+more\n"
    text, numbers = gh._added_lines(patch)
    assert gh.locate_secrets(text, "a.py", line_numbers=numbers)[0][1] == 21


def test_the_connector_is_listed_with_setup_text(client):
    p = client.get("/api/discovery/connectors").json()["platforms"]["github_secrets"]
    assert "token" in p["credential_fields"] and "READ-ONLY" in p["setup"]
