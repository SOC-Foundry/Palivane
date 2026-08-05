"""Third-party scanner integration: normalizers + /api/scan/import + verified escalation."""

from __future__ import annotations

import json

from app import scanner_import as si
from app.detectors.secrets_at_rest import SecretsAtRestDetector
from app.detectors.base import AnalysisInput, Surface

_d = SecretsAtRestDetector()


# --- normalizers ----------------------------------------------------------------------

_TRUFFLEHOG_JSONL = "\n".join([
    json.dumps({"DetectorName": "Github", "Verified": True, "Raw": "ghp_LIVEabcdefghijklmnop",
                "SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/.env", "line": 4}}}}),
    json.dumps({"DetectorName": "AWS", "Verified": False, "Raw": "AKIAIOSFODNN7EXAMPLE",
                "SourceMetadata": {"Data": {"Git": {"file": "config.tf", "line": 9,
                                                    "repository": "git@x/y"}}}}),
])


def test_normalize_trufflehog_masks_and_maps():
    out = si.normalize_trufflehog(_TRUFFLEHOG_JSONL)
    assert len(out) == 2
    gh = out[0]
    assert gh["secret_types"] == ["GitHub token"]        # detector name -> Warden label
    assert gh["path"] == "/repo/.env" and gh["line"] == 4
    assert gh["verified"] is True and gh["source"] == "trufflehog"
    assert "LIVEabcdefghijklmnop" not in gh["masked"] and "••••" in gh["masked"]  # masked
    assert out[1]["secret_types"] == ["AWS access key id"] and out[1]["verified"] is False


def test_normalize_gitleaks():
    arr = json.dumps([{"RuleID": "github-pat", "Secret": "ghp_secretsecretsecret",
                       "File": "src/app.py", "StartLine": 12}])
    out = si.normalize_gitleaks(arr)
    assert out[0]["secret_types"] == ["GitHub token"] and out[0]["line"] == 12
    assert out[0]["verified"] is False and out[0]["source"] == "gitleaks"
    assert "secretsecret" not in out[0]["masked"]


def test_normalize_gitguardian_best_effort():
    doc = json.dumps({"entities_with_incidents": [
        {"filename": "prod.env", "incidents": [
            {"type": "AWS Keys", "validity": "valid",
             "matches": [{"match": "AKIAABCDEFGHIJKLMNOP", "line_start": 3}]}]}]})
    out = si.normalize_gitguardian(doc)
    assert out[0]["path"] == "prod.env" and out[0]["verified"] is True
    assert out[0]["source"] == "gitguardian"


def test_unknown_tool_returns_empty():
    assert si.normalize("bogus", "[]") == []


# --- verified escalation in the detector ----------------------------------------------

def _weight(secret_type, verified):
    sigs = _d.analyze(AnalysisInput(content="x", surface=Surface.SECRETS,
                                    metadata={"secret_types": [secret_type], "path": "/x",
                                              "verified": verified, "source": "trufflehog"}))
    return sigs[0].weight


def test_verified_live_escalates():
    base = _weight("GitHub token", verified=False)
    live = _weight("GitHub token", verified=True)
    assert live > base and live >= 0.9        # verified GitHub token -> critical band


def test_verified_tag_in_title():
    sigs = _d.analyze(AnalysisInput(content="x", surface=Surface.SECRETS,
                                    metadata={"secret_types": ["AWS access key id"], "path": "/x",
                                              "verified": True, "source": "trufflehog"}))
    assert "VERIFIED LIVE" in sigs[0].title
    assert "trufflehog" in sigs[0].detail


# --- endpoint -------------------------------------------------------------------------

def test_scan_import_endpoint_records(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "imp", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/import",
                        json={"tool": "trufflehog", "results": _TRUFFLEHOG_JSONL, "host": "ci-1"},
                        headers={"X-Palivane-Token": key}).json()
    assert r["scanned"] == 2
    assert r["verified_live"] == 1
    by_path = {f["path"]: f for f in r["findings"]}
    assert by_path["/repo/.env"]["severity"] == "critical"   # verified live -> critical
    # persisted as secrets-surface findings
    findings = client.get("/api/findings?surface=secrets").json()["findings"]
    assert len(findings) == 2


def test_scan_import_unknown_tool_400(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "imp2", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/import", json={"tool": "nope", "results": "[]"},
                        headers={"X-Palivane-Token": key})
    assert r.status_code == 400
