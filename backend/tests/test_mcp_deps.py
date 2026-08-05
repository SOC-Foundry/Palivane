"""MCP server dependency scanning: launcher -> package resolution + unpinned flagging."""

from __future__ import annotations

import json

from app.detectors.dep_guard import extract_mcp_packages


def test_extract_npm_and_pypi():
    assert extract_mcp_packages("npx", ["-y", "@scope/srv@1.2.3"]) == [("npm", "@scope/srv", "1.2.3")]
    assert extract_mcp_packages("npx", ["-y", "@scope/srv"]) == [("npm", "@scope/srv", "")]
    assert extract_mcp_packages("uvx", ["mcp-server==2.0.0"]) == [("PyPI", "mcp-server", "2.0.0")]
    assert extract_mcp_packages("uvx", ["mcp-server"]) == [("PyPI", "mcp-server", "")]


def test_extract_ignores_local_and_bare():
    assert extract_mcp_packages("node", ["/home/me/server.js"]) == []
    assert extract_mcp_packages("python", ["-m", "myserver"]) == []
    assert extract_mcp_packages("npx", ["-y", "./local/pkg"]) == []


def test_mcp_config_flags_pinned_cve(client, raw_client, monkeypatch):
    import app.main as main
    import app.osv as osv
    monkeypatch.setattr(main.settings, "dep_osv_enabled", True)
    # Pretend the pinned package has a known advisory.
    monkeypatch.setattr(osv, "query", lambda pins: {("npm", "@acme/mcp-files", "1.0.0"): ["CVE-2026-9999"]})
    key = client.post("/api/apikeys", json={"label": "ci", "actor": "ci@acme.com"}).json()["token"]
    cfg = json.dumps({"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@acme/mcp-files@1.0.0"]},   # pinned -> OSV
    }})
    r = raw_client.post("/api/scan/mcp-config", json={"content": cfg},
                        headers={"X-Palivane-Token": key})
    assert r.status_code == 200
    srv = next((s for s in r.json()["servers"] if s["name"] == "files"), None)
    assert srv is not None and srv["severity"] == "critical"
    assert any(sig["detector"] == "osv" and "CVE-2026-9999" in sig["evidence"] for sig in srv["signals"])


def test_clean_unpinned_config_still_allowed(client, raw_client):
    # Unpinned npx (the common case) must NOT be flagged — no noise.
    key = client.post("/api/apikeys", json={"label": "ci", "actor": "ci@acme.com"}).json()["token"]
    cfg = json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["-y", "server-fs", "./data"]}}})
    r = raw_client.post("/api/scan/mcp-config", json={"content": cfg}, headers={"X-Palivane-Token": key})
    assert r.status_code == 200 and r.json()["action"] == "allow"
