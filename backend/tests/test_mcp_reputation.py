"""MCP server reputation/provenance — the postmark-mcp trusted-then-trojaned gap beyond
allowlist + TOFU pinning."""

from __future__ import annotations

import json

import app.mcp_reputation as mr


# --- non-registry source (offline) --------------------------------------------------------

def test_non_registry_source_flags_git_url_tarball():
    assert mr.non_registry_source("npx", ["-y", "github:evil/mcp"])
    assert mr.non_registry_source("npx", ["-y", "https://evil.sh/x.tgz"])
    assert mr.non_registry_source("uvx", ["git+https://evil/repo.git"])
    assert mr.non_registry_source("npx", ["-y", "@modelcontextprotocol/server-github"]) is None
    assert mr.non_registry_source("node", ["server.js"]) is None   # not a package runner


# --- denylist (offline) -------------------------------------------------------------------

def test_denylist_matches_name_or_package(monkeypatch):
    monkeypatch.setattr(mr.settings, "mcp_server_denylist", "postmark-mcp, evil-server")
    by_name = mr.assess("postmark-mcp", "npx", ["-y", "postmark-mcp"],
                        [("npm", "postmark-mcp", "1.0.0")], check_registry=False)
    assert any(s["title"] == "Known-bad MCP server" for s in by_name)
    by_pkg = mr.assess("mailer", "npx", ["-y", "evil-server"],
                       [("npm", "evil-server", "")], check_registry=False)
    assert any(s["title"] == "Known-bad MCP server" for s in by_pkg)


def test_clean_registry_server_no_signals(monkeypatch):
    monkeypatch.setattr(mr.settings, "mcp_server_denylist", "")
    assert mr.assess("gh", "npx", ["-y", "@scope/server-github"],
                     [("npm", "@scope/server-github", "1.2.3")], check_registry=False) == []


# --- registry freshness (opt-in, mocked network) ------------------------------------------

def _mock_npm(monkeypatch, created, latest_ts, latest="2.0.0"):
    doc = {"dist-tags": {"latest": latest},
           "time": {"created": created, latest: latest_ts, "modified": latest_ts}}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(doc).encode()

    monkeypatch.setattr(mr.urllib.request, "urlopen", lambda *a, **k: _Resp())


def test_freshness_flags_republished_old_package(monkeypatch):
    # Established package (created years ago) with a version shipped 2 days ago = takeover shape.
    _mock_npm(monkeypatch, created="2021-01-01T00:00:00.000Z",
              latest_ts="2026-08-02T00:00:00.000Z")
    monkeypatch.setattr(mr.settings, "mcp_reputation_fresh_days", 14)
    info = mr.registry_freshness("npm", "postmark-mcp")
    assert info["republished"] is True and info["age_days"] > 90

    sigs = mr.assess("postmark-mcp", "npx", ["-y", "postmark-mcp"],
                     [("npm", "postmark-mcp", "")], check_registry=True)
    assert any("republished" in s["title"] for s in sigs)


def test_freshness_flags_brand_new_package(monkeypatch):
    _mock_npm(monkeypatch, created="2026-07-31T00:00:00.000Z",
              latest_ts="2026-07-31T00:00:00.000Z")
    monkeypatch.setattr(mr.settings, "mcp_reputation_fresh_days", 14)
    sigs = mr.assess("newthing", "npx", ["-y", "newthing"],
                     [("npm", "newthing", "")], check_registry=True)
    assert any("Brand-new" in s["title"] for s in sigs)


def test_freshness_fails_open(monkeypatch):
    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(mr.urllib.request, "urlopen", boom)
    assert mr.registry_freshness("npm", "whatever") is None     # never raises
    assert mr.registry_freshness("PyPI", "x") is None           # npm-only for now


# --- end-to-end through /api/scan/mcp-config ----------------------------------------------

def test_scan_mcp_config_flags_denylisted_server(client, raw_client, monkeypatch):
    monkeypatch.setattr(mr.settings, "mcp_server_denylist", "postmark-mcp")
    key = client.post("/api/apikeys", json={"label": "posture", "actor": "d@a.com"}).json()["token"]
    cfg = json.dumps({"mcpServers": {
        "postmark-mcp": {"command": "npx", "args": ["-y", "postmark-mcp"]}}})
    r = raw_client.post("/api/scan/mcp-config",
                        json={"content": cfg, "path": ".mcp.json", "record": True},
                        headers={"X-Palivane-Token": key})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in ("warn", "block")
    cats = {s["category"] for srv in body["servers"] for s in srv["signals"]}
    assert "mcp_reputation" in cats


def test_scan_mcp_config_clean_server_allows(client, raw_client, monkeypatch):
    monkeypatch.setattr(mr.settings, "mcp_server_denylist", "")
    key = client.post("/api/apikeys", json={"label": "posture", "actor": "d@a.com"}).json()["token"]
    cfg = json.dumps({"mcpServers": {
        "gh": {"command": "npx", "args": ["-y", "@scope/server-github"]}}})
    r = raw_client.post("/api/scan/mcp-config",
                        json={"content": cfg, "path": ".mcp.json", "record": True},
                        headers={"X-Palivane-Token": key})
    assert r.status_code == 200
    cats = {s["category"] for srv in r.json()["servers"] for s in srv["signals"]}
    assert "mcp_reputation" not in cats
