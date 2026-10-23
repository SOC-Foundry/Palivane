"""GitHub push webhooks: the signature gate, what a push is allowed to name, and that a push scan
stores the same masked finding a scheduled scan does."""

from __future__ import annotations

import json

import pytest

import app.database as db_mod
import app.github_webhook as gw
import app.saas_connectors as sc
from app.models import Finding

AWS = "AK" + "IA" + "4YTGH2NBQF7XZP3K"
OAI = "sk-" + "proj-" + "abcDEF123456ghiJKL789012mnoPQR"
TOKEN = "github_pat_" + "11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuv"
SHA1, SHA2, SHA3 = "a" * 40, "b" * 40, "c" * 40
ZERO = "0" * 40


class FakeGitHub:
    def __init__(self):
        self.calls: list[str] = []
        self.files = {
            SHA1: [{"filename": "deploy.sh", "status": "modified",
                    "patch": f'@@ -1 +1,2 @@\n x\n+KEY = "{AWS}"\n'}],
            SHA2: [{"filename": "branch.py", "status": "added", "patch": f'@@ -0,0 +1 @@\n+T = "{OAI}"\n'}],
            SHA3: [{"filename": "clean.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1\n"}],
        }
        self.compare = [SHA1, SHA2, SHA3]

    def __call__(self, url, **kw):
        path = url.replace("https://api.github.com", "")
        self.calls.append(path)
        base = path.split("?")[0]
        if base == "/rate_limit":
            return {"resources": {"core": {"remaining": 5000}}}
        if "/compare/" in base:
            return {"commits": [{"sha": s, "parents": [{}]} for s in self.compare]}
        if "/commits/" in base:
            return {"commit": {"author": {"email": "dev@acme.com"}}, "files": self.files[base.rsplit("/", 1)[1]]}
        raise AssertionError("unexpected GitHub call: " + path)


@pytest.fixture
def hook(client, db_factory, monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(sc, "_http_json", fake)
    monkeypatch.setattr(gw, "_submit", lambda fn, *a: fn(*a))          # run the worker inline
    monkeypatch.setattr(db_mod, "SessionLocal", db_factory)           # and on the test database
    gw._SEEN.clear()
    gw._FAILS.clear()
    r = client.post("/api/discovery/connectors", json={
        "platform": "github_secrets", "label": "acme", "credentials": {"token": TOKEN, "org": "acme"}})
    fake.id = r.json()["id"]
    fake.client = client
    fake.secret = client.post(f"/api/discovery/connectors/{fake.id}/github-webhook").json()["secret"]
    return fake


def _push(hook, raw_client, *, ref="refs/heads/main", commits=None, before=SHA3, after=SHA1,
          repo="acme/app", secret=None, delivery="d-1", event="push", extra=None, body_override=None):
    payload = {"ref": ref, "before": before, "after": after, "deleted": False,
               "repository": {"full_name": repo, "default_branch": "main", "private": True},
               "commits": commits if commits is not None else [{"id": SHA1, "distinct": True}], **(extra or {})}
    body = body_override or json.dumps(payload).encode()
    headers = {"X-Hub-Signature-256": gw.sign(secret if secret is not None else hook.secret, body),
               "X-GitHub-Event": event, "X-GitHub-Delivery": delivery, "content-type": "application/json"}
    return raw_client.post(f"/api/webhooks/github/{hook.id}", content=body, headers=headers)


def _findings(db_factory):
    db = db_factory()
    try:
        return [(f.subject, json.dumps(f.signals, ensure_ascii=False)) for f in db.query(Finding).order_by(Finding.id)]
    finally:
        db.close()


# --- setup -------------------------------------------------------------------------------------

def test_enabling_returns_the_url_and_the_secret_once(client, hook):
    again = client.post(f"/api/discovery/connectors/{hook.id}/github-webhook").json()
    assert again["url"].endswith(f"/api/webhooks/github/{hook.id}") and again["events"] == ["push"]
    assert again["secret"] != hook.secret                                  # rotating replaces it
    listing = json.dumps(client.get("/api/discovery/connectors").json())
    assert again["secret"] not in listing and hook.secret not in listing   # never readable again
    row = next(c for c in client.get("/api/discovery/connectors").json()["connectors"] if c["id"] == hook.id)
    assert row["options"]["webhook_secret"] is True                         # only that it is set


def test_saving_the_connector_again_keeps_the_webhook_on(client, hook, raw_client):
    client.post("/api/discovery/connectors", json={
        "platform": "github_secrets", "label": "acme",
        "credentials": {"token": TOKEN, "org": "acme", "branches": "all"}})
    assert _push(hook, raw_client).status_code == 200                       # the same secret still verifies


def test_only_an_admin_can_enable_it(client, raw_client, hook):
    r = raw_client.post(f"/api/discovery/connectors/{hook.id}/github-webhook")
    assert r.status_code in (401, 403)


def test_turning_it_off_stops_accepting_pushes(client, raw_client, hook):
    assert client.delete(f"/api/discovery/connectors/{hook.id}/github-webhook").status_code == 200
    assert _push(hook, raw_client).status_code == 401


# --- the gate ----------------------------------------------------------------------------------

def test_a_wrong_signature_is_refused_and_nothing_is_read(hook, raw_client, db_factory):
    r = _push(hook, raw_client, secret="not-the-secret")
    assert r.status_code == 401 and _findings(db_factory) == [] and not any("/commits/" in c for c in hook.calls)


def test_an_unknown_connector_and_one_without_a_secret_fail_the_same_way(client, hook, raw_client):
    body = b"{}"
    sig = {"X-Hub-Signature-256": gw.sign("x", body), "X-GitHub-Event": "push"}
    unknown = raw_client.post("/api/webhooks/github/99999", content=body, headers=sig)
    client.delete(f"/api/discovery/connectors/{hook.id}/github-webhook")
    unset = raw_client.post(f"/api/webhooks/github/{hook.id}", content=body, headers=sig)
    assert unknown.status_code == unset.status_code == 401
    assert unknown.json() == unset.json()


def test_a_missing_signature_header_is_refused(hook, raw_client):
    r = raw_client.post(f"/api/webhooks/github/{hook.id}", content=b"{}", headers={"X-GitHub-Event": "push"})
    assert r.status_code == 401


def test_a_body_that_was_changed_after_signing_is_refused(hook, raw_client):
    good = json.dumps({"ref": "refs/heads/main"}).encode()
    r = raw_client.post(f"/api/webhooks/github/{hook.id}", content=good + b" ",
                        headers={"X-Hub-Signature-256": gw.sign(hook.secret, good), "X-GitHub-Event": "push"})
    assert r.status_code == 401


def test_repeated_bad_signatures_from_one_address_are_cut_off(hook, raw_client, monkeypatch):
    monkeypatch.setattr(gw, "_FAIL_LIMIT", 3)
    codes = [_push(hook, raw_client, secret="nope", delivery=f"x{i}").status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401] and 429 in codes[3:]


def test_a_ping_is_answered_and_reads_nothing(hook, raw_client):
    r = _push(hook, raw_client, event="ping")
    assert r.status_code == 200 and r.json()["pong"] is True and not hook.calls[1:]


def test_other_events_are_acknowledged_and_ignored(hook, raw_client):
    r = _push(hook, raw_client, event="issues")
    assert r.status_code == 200 and r.json()["ignored"] == "issues"


# --- what a push does --------------------------------------------------------------------------

def test_a_push_scans_its_commits_and_stores_a_masked_finding(hook, raw_client, db_factory):
    assert _push(hook, raw_client).status_code == 200
    rows = _findings(db_factory)
    assert [s for s, _ in rows] == ["acme/app/deploy.sh"]
    assert "AKIA••••ZP3K" in rows[0][1] and AWS not in rows[0][1]


def test_a_redelivery_is_processed_once(hook, raw_client):
    _push(hook, raw_client, delivery="same")
    n = sum("/commits/" in c for c in hook.calls)
    assert _push(hook, raw_client, delivery="same").json().get("duplicate") is True
    assert sum("/commits/" in c for c in hook.calls) == n


def test_a_push_to_another_branch_is_ignored_unless_the_connector_reads_all(client, hook, raw_client, db_factory):
    args = dict(ref="refs/heads/feature/x", commits=[{"id": SHA2, "distinct": True}], after=SHA2, before=ZERO)
    _push(hook, raw_client, **args)
    assert _findings(db_factory) == []
    client.post("/api/discovery/connectors", json={"platform": "github_secrets", "label": "acme",
                                                   "credentials": {"token": TOKEN, "org": "acme", "branches": "all"}})
    _push(hook, raw_client, delivery="d-2", **args)
    rows = dict(_findings(db_factory))
    assert any(c.startswith("/repos/acme/app/compare/main...") for c in hook.calls)    # a new branch: compare to default
    assert "on branch feature/x" in rows["acme/app/branch.py"]


def test_tags_and_deleted_branches_are_ignored(hook, raw_client):
    _push(hook, raw_client, ref="refs/tags/v1")
    _push(hook, raw_client, delivery="d-2", extra={"deleted": True})
    assert not any("/commits/" in c for c in hook.calls)


def test_a_repository_outside_the_connectors_scope_is_ignored(client, hook, raw_client):
    _push(hook, raw_client, repo="other-org/app")
    client.post("/api/discovery/connectors", json={"platform": "github_secrets", "label": "acme",
                                                   "credentials": {"token": TOKEN, "org": "acme", "exclude": "app"}})
    _push(hook, raw_client, delivery="d-2")
    assert not any("/commits/" in c for c in hook.calls)


def test_a_signed_payload_cannot_put_anything_odd_into_a_github_url(hook, raw_client):
    _push(hook, raw_client, repo="acme/../../orgs/x")
    _push(hook, raw_client, delivery="d-2", commits=[{"id": "../../../admin", "distinct": True}], after=SHA1)
    assert not any(".." in c for c in hook.calls)


def test_a_long_push_asks_github_for_the_rest(hook, raw_client, db_factory):
    many = [{"id": SHA3, "distinct": True} for _ in range(20)]
    _push(hook, raw_client, commits=many)
    assert any("/compare/" in c for c in hook.calls)
    assert "acme/app/deploy.sh" in {s for s, _ in _findings(db_factory)}


def test_commits_already_on_another_branch_are_not_read_again(hook, raw_client):
    _push(hook, raw_client, commits=[{"id": SHA1, "distinct": False}])
    assert not any("/commits/" in c for c in hook.calls)


def test_a_failing_scan_does_not_break_the_response(hook, raw_client, monkeypatch):
    def boom(*a, **k):
        raise sc.ConnectorError("HTTP 500 from api.github.com")
    monkeypatch.setattr(sc, "_http_json", boom)
    assert _push(hook, raw_client).status_code == 200


def test_a_push_respects_the_excluded_paths(client, hook, raw_client, db_factory):
    client.post("/api/discovery/connectors", json={"platform": "github_secrets", "label": "acme",
                                                   "credentials": {"token": TOKEN, "org": "acme",
                                                                   "exclude_paths": "deploy.sh"}})
    _push(hook, raw_client)
    assert _findings(db_factory) == []


# --- a failed scan is not "seen" (SEC-05, #299) ------------------------------------------------------

def _failing_once(hook, monkeypatch, error):
    box = {"failed": False}

    def flaky(url, **kw):
        if "/commits/" in url and not box["failed"]:
            box["failed"] = True
            hook.calls.append(url)
            raise error
        return hook(url, **kw)
    monkeypatch.setattr(sc, "_http_json", flaky)


def test_a_redelivery_of_a_failed_scan_is_scanned(hook, raw_client, db_factory, monkeypatch):
    _failing_once(hook, monkeypatch, sc.ConnectorError("HTTP 502 from api.github.com: bad gateway"))
    assert _push(hook, raw_client, delivery="retry-me").json() == {"ok": True}
    assert _findings(db_factory) == []                                # the commit did not load
    second = _push(hook, raw_client, delivery="retry-me").json()
    assert not second.get("duplicate")                                # not "seen": it runs
    assert [s for s, _ in _findings(db_factory)] == ["acme/app/deploy.sh"]
    assert _push(hook, raw_client, delivery="retry-me").json().get("duplicate") is True   # now it is


def test_a_redelivery_of_a_rate_limited_scan_is_scanned(hook, raw_client, db_factory, monkeypatch):
    _failing_once(hook, monkeypatch, sc.ConnectorError("HTTP 429 from api.github.com: rate limit"))
    _push(hook, raw_client, delivery="limited")
    assert not _push(hook, raw_client, delivery="limited").json().get("duplicate")
    assert [s for s, _ in _findings(db_factory)] == ["acme/app/deploy.sh"]


def test_a_scan_that_crashed_is_forgotten(hook, raw_client, monkeypatch):
    from app import github_secrets

    def boom(*a, **k):
        raise RuntimeError("worker died")
    monkeypatch.setattr(github_secrets, "scan_push", boom)
    _push(hook, raw_client, delivery="crash")
    assert "crash" not in gw._SEEN


def test_a_delivery_still_being_scanned_is_not_scanned_twice(hook, raw_client, monkeypatch):
    queued = []
    monkeypatch.setattr(gw, "_submit", lambda fn, *a: queued.append(a))    # the worker has not run yet
    _push(hook, raw_client, delivery="slow")
    assert _push(hook, raw_client, delivery="slow").json().get("duplicate") is True
    assert len(queued) == 1
