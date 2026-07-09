"""Agent identity (Phase 0): mint, authenticate, attribute findings, rotate/disable."""

from __future__ import annotations


def test_agent_crud_and_token_once(client):
    r = client.post("/api/agents", json={"name": "billing-bot", "kind": "service"})
    assert r.status_code == 200
    body = r.json()
    assert body["token"].startswith("ag_") and body["name"] == "billing-bot"
    # listed, token not returned again
    agents = client.get("/api/agents").json()["agents"]
    assert any(a["name"] == "billing-bot" for a in agents)
    assert "token" not in agents[0]
    # duplicate name rejected
    assert client.post("/api/agents", json={"name": "billing-bot"}).status_code == 409


def test_agent_token_authenticates_and_attributes(client, raw_client):
    token = client.post("/api/agents", json={"name": "research-agent"}).json()["token"]
    # The agent uses its OWN ag_ token as the capture credential.
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "SSN 123-45-6789", "destination": "https://chatgpt.com/"},
                        headers={"X-Warden-Token": token})
    assert r.status_code == 200
    # The finding is attributed to the agent.
    findings = client.get("/api/findings").json()["findings"]
    assert any(f.get("agent") == "research-agent" for f in findings)


def test_agent_header_alongside_api_key(client, raw_client):
    client.post("/api/agents", json={"name": "svc-agent"})
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    r = raw_client.post("/api/ingest/mcp",
                        json={"method": "tools/call", "server": "local", "tool": "run",
                              "args_text": "rm -rf / --no-preserve-root"},
                        headers={"X-Warden-Token": key, "X-Warden-Agent": _agtoken(client, "svc-agent")})
    assert r.status_code == 200
    findings = client.get("/api/findings").json()["findings"]
    assert any(f.get("agent") == "svc-agent" for f in findings)


def _agtoken(client, name):
    # rotate returns a fresh token for an existing agent
    aid = next(a["id"] for a in client.get("/api/agents").json()["agents"] if a["name"] == name)
    return client.post(f"/api/agents/{aid}/rotate").json()["token"]


def test_disabled_agent_token_rejected(client, raw_client):
    token = client.post("/api/agents", json={"name": "temp-agent"}).json()["token"]
    aid = next(a["id"] for a in client.get("/api/agents").json()["agents"] if a["name"] == "temp-agent")
    assert client.delete(f"/api/agents/{aid}").status_code == 200
    # A disabled agent's token no longer authenticates the ingest endpoint.
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Warden-Token": token})
    assert r.status_code == 401


def test_rotate_invalidates_old_token(client, raw_client):
    old = client.post("/api/agents", json={"name": "rot-agent"}).json()["token"]
    aid = next(a["id"] for a in client.get("/api/agents").json()["agents"] if a["name"] == "rot-agent")
    client.post(f"/api/agents/{aid}/rotate")
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Warden-Token": old})
    assert r.status_code == 401
