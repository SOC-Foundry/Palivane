"""Git capture plane: /api/scan/code — pre-commit hook / CI secret & PII scanning."""

from __future__ import annotations

import app.main as main
from app import users as users_cli


def _seed_tenant(db_factory, slug="acme"):
    db = db_factory()
    users_cli.create_tenant(db, slug, slug.title())
    db.close()


def _scan(raw_client, files, token="ext-secret", record=False):
    return raw_client.post(
        "/api/scan/code",
        json={"files": files, "record": record},
        headers={"X-Palivane-Token": token},
    )


def test_requires_valid_token(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    assert raw_client.post("/api/scan/code", json={"files": []}).status_code == 401
    assert _scan(raw_client, [{"path": "a.py", "content": "x"}], token="nope").status_code == 401


def test_clean_code_is_allowed(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    body = _scan(raw_client, [{"path": "util.py", "content": "def add(a, b):\n    return a + b\n"}]).json()
    assert body["action"] == "allow"
    assert body["files"] == []
    assert body["scanned"] == 1


def test_source_code_is_not_flagged_as_leak(raw_client, db_factory, monkeypatch):
    # A repo is *meant* to hold code — source_code_leak is dropped on this surface, so a
    # confidential-looking code file with no secret/PII is allowed.
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    code = "# CONFIDENTIAL internal module\nclass Engine:\n    def run(self): return 42\n"
    body = _scan(raw_client, [{"path": "engine.py", "content": code}]).json()
    assert body["action"] == "allow"


def test_secret_blocks(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    body = _scan(raw_client, [{"path": "prod.env", "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"}]).json()
    assert body["action"] == "block"
    assert body["files"][0]["path"] == "prod.env"
    assert body["files"][0]["action"] == "block"
    assert any(s["category"] == "secret_leak" for s in body["files"][0]["signals"])


def test_pii_blocks(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    body = _scan(raw_client, [{"path": "data.csv", "content": "name,ssn\nJane,123-45-6789\n"}]).json()
    assert body["action"] == "block"
    assert any(s["category"] == "pii_exposure" for s in body["files"][0]["signals"])


def test_per_file_results_and_overall_worst(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    body = _scan(raw_client, [
        {"path": "ok.py", "content": "print('hi')\n"},
        {"path": "secret.env", "content": "token=AKIAIOSFODNN7EXAMPLE\n"},
    ]).json()
    assert body["scanned"] == 2
    assert body["action"] == "block"            # worst-of
    assert {f["path"] for f in body["files"]} == {"secret.env"}   # only non-clean returned


def test_record_persists_only_flagged(client, raw_client):
    # Mint a per-tenant key (like a CI credential), scan with record=True.
    key = client.post("/api/apikeys", json={"label": "git", "actor": "ci@acme.com"}).json()["token"]
    _scan(raw_client, [
        {"path": "ok.py", "content": "print('hi')\n"},
        {"path": "leak.env", "content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"},
    ], token=key, record=True)
    findings = client.get("/api/findings").json()["findings"]
    git_findings = [f for f in findings if f["channel"] == "git"]
    assert len(git_findings) == 1      # only the flagged file persisted, not the clean one
    assert git_findings[0]["surface"] == "ai_usage"

# --- client-side detection (metadata only) ------------------------------------------------
# palivane-github-scan reads a repo over the GitHub API, detects on its own machine, and
# sends findings. An --org sweep used to upload every text blob of every private repo here.

def _finding(category="secret_leak", label="AWS access key id", line=1, masked="AKIA••••MPLE"):
    return {"category": category, "label": label, "line": line, "masked": masked}


def _setup(db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")


def test_client_findings_are_scored_without_any_file_text(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"path": "acme/api@main:.env", "findings": [_finding()]}]).json()
    assert body["action"] == "block"
    f = body["files"][0]
    assert f["path"] == "acme/api@main:.env" and f["risk_score"] >= 70
    assert any(s["category"] == "secret_leak" for s in f["signals"])


def test_no_file_text_is_required_or_echoed(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    r = _scan(raw_client, [{"path": "acme/api@main:prod.tf",
                            "findings": [_finding(masked="AKIA••••7777")]}])
    assert "AKIAIOSFODNN7EXAMPLE" not in r.text
    assert "content" not in r.json()["files"][0]


def test_entropy_findings_stay_below_the_block_line(raw_client, db_factory, monkeypatch):
    """The client's tier-2 heuristic must not hard-block a repo on 'looks random'. The
    label IS the tier marker, so this also pins the client/server title agreement."""
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"path": "acme/api@main:build.js", "findings": [
        _finding(label="Possible secret (high-entropy token)", masked="a1b2••••y9z0")]}]).json()
    assert body["action"] == "warn"


def test_pii_and_phi_categories_are_accepted(raw_client, db_factory, monkeypatch):
    _setup(db_factory, monkeypatch)
    for cat in ("pii_exposure", "phi_exposure"):
        body = _scan(raw_client, [{"path": f"acme/api@main:{cat}.csv", "findings": [
            _finding(category=cat, label="US Social Security number",
                     masked="412-••••7390")]}]).json()
        assert body["files"], f"{cat} produced no finding"
        assert body["files"][0]["action"] in ("warn", "block")


def test_recorded_verdict_matches_the_response(raw_client, db_factory, monkeypatch):
    """The response said 'high' while the stored row said 'benign', so a recorded sweep
    left every finding invisible in the console. One analysis now serves both."""
    from app.models import Finding
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"path": "acme/api@main:.env", "findings": [_finding()]}],
                 record=True).json()
    db = db_factory()
    rows = db.query(Finding).all()
    db.close()
    assert len(rows) == 1
    assert rows[0].severity == body["files"][0]["severity"]
    assert rows[0].risk_score == body["files"][0]["risk_score"]


def test_clean_files_are_not_recorded(raw_client, db_factory, monkeypatch):
    from app.models import Finding
    _setup(db_factory, monkeypatch)
    _scan(raw_client, [{"path": "util.py", "content": "def add(a, b):\n    return a + b\n"}],
          record=True)
    db = db_factory()
    assert db.query(Finding).count() == 0
    db.close()


def test_precommit_content_path_still_works(raw_client, db_factory, monkeypatch):
    """The hook scans a file on the machine the request came from, so it still sends text."""
    _setup(db_factory, monkeypatch)
    body = _scan(raw_client, [{"path": "cfg.py", "content": "KEY = 'AKIAIOSFODNN7EXAMPLE'\n"}]).json()
    assert body["action"] in ("warn", "block") and body["files"]
