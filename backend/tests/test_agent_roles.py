"""Agent least-privilege (Phase 1): authorize() logic + monitor/enforce on MCP calls."""

from __future__ import annotations

from app.authz import authorize


def _role(**kw):
    base = {"name": "r", "allow_tools": [], "allow_servers": [], "deny": [],
            "default_allow": False, "enforce": False}
    base.update(kw)
    return base


def test_authorize_rules():
    # default-deny with no allow-list
    ok, _ = authorize(_role(), "srv", "tool"); assert ok is False
    # default-allow
    ok, _ = authorize(_role(default_allow=True), "srv", "tool"); assert ok is True
    # allow-list match / miss
    r = _role(allow_tools=["invoices.*"], allow_servers=["mcp.acme.*"])
    assert authorize(r, "mcp.acme.internal", "invoices.read")[0] is True
    assert authorize(r, "mcp.acme.internal", "payroll.read")[0] is False
    assert authorize(r, "evil.example", "invoices.read")[0] is False
    # explicit deny wins over allow
    r2 = _role(allow_tools=["*"], deny=["*delete*"])
    assert authorize(r2, "srv", "invoices.delete")[0] is False
    assert authorize(r2, "srv", "invoices.read")[0] is True


def _mkagent(client, name, role=""):
    tok = client.post("/api/agents", json={"name": name}).json()["token"]
    if role:
        aid = next(a["id"] for a in client.get("/api/agents").json()["agents"] if a["name"] == name)
        client.patch(f"/api/agents/{aid}", json={"role": role})
    return tok


def _mcp(raw_client, tok, server, tool):
    return raw_client.post("/api/ingest/mcp",
                           json={"method": "tools/call", "server": server, "tool": tool},
                           headers={"X-Palivane-Token": tok}).json()


def test_monitor_role_warns_but_allows(client, raw_client):
    client.post("/api/agent-roles", json={"name": "billing", "allow_tools": ["invoices.*"],
                                          "enforce": False})
    tok = _mkagent(client, "bill-bot", "billing")
    # out-of-role call: monitor -> recorded/warned, not blocked
    out = _mcp(raw_client, tok, "mcp.acme", "payroll.read")
    cats = {s["category"] for s in out["signals"]}
    assert "agent_authz" in cats
    assert out["action"] in ("allow", "warn")   # monitor never blocks
    # in-role call: no authz signal
    ok = _mcp(raw_client, tok, "mcp.acme", "invoices.read")
    assert "agent_authz" not in {s["category"] for s in ok["signals"]}


def test_enforce_role_blocks(client, raw_client):
    client.post("/api/agent-roles", json={"name": "ro", "allow_tools": ["read.*"], "enforce": True})
    tok = _mkagent(client, "ro-bot", "ro")
    out = _mcp(raw_client, tok, "mcp.acme", "delete.everything")
    assert out["action"] == "block"
    assert any(s["category"] == "agent_authz" for s in out["signals"])


def test_agentless_or_roleless_not_authorized(client, raw_client):
    # An agent with no role assigned isn't constrained.
    tok = _mkagent(client, "free-bot")
    out = _mcp(raw_client, tok, "anything", "anything")
    assert "agent_authz" not in {s["category"] for s in out["signals"]}


def test_delete_role_unassigns_agents(client, raw_client):
    client.post("/api/agent-roles", json={"name": "temp", "enforce": True})
    tok = _mkagent(client, "t-bot", "temp")
    rid = next(r["id"] for r in client.get("/api/agent-roles").json()["roles"] if r["name"] == "temp")
    assert client.delete(f"/api/agent-roles/{rid}").status_code == 200
    # role gone -> agent unconstrained again
    out = _mcp(raw_client, tok, "srv", "tool")
    assert "agent_authz" not in {s["category"] for s in out["signals"]}
