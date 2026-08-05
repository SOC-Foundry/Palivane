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
                        headers={"X-Palivane-Token": token})
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
                        headers={"X-Palivane-Token": key, "X-Palivane-Agent": _agtoken(client, "svc-agent")})
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
                        headers={"X-Palivane-Token": token})
    assert r.status_code == 401


def test_rotate_invalidates_old_token(client, raw_client):
    old = client.post("/api/agents", json={"name": "rot-agent"}).json()["token"]
    aid = next(a["id"] for a in client.get("/api/agents").json()["agents"] if a["name"] == "rot-agent")
    client.post(f"/api/agents/{aid}/rotate")
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": old})
    assert r.status_code == 401


# --- Phase 1: short-lived session tokens + per-agent gateway policy ---------------------

def _make_agent(client, name="phase1-bot"):
    return client.post("/api/agents", json={"name": name}).json()


def test_session_token_mints_and_authenticates_on_gateway(client, raw_client):
    ag = _make_agent(client, "session-bot")
    r = client.post(f"/api/agents/{ag['id']}/token", json={"ttl_minutes": 30})
    assert r.status_code == 200
    body = r.json()
    assert body["expires_in"] == 1800 and body["agent"] == "session-bot"
    # The JWT works as the gateway credential (no upstream configured -> stub) and the
    # call is attributed to the agent.
    g = raw_client.post("/v1/messages",
                        json={"model": "claude-sonnet-4-6", "max_tokens": 16,
                              "messages": [{"role": "user", "content": "hello"}]},
                        headers={"x-api-key": body["token"]})
    assert g.status_code == 200


def test_session_token_rejected_when_agent_disabled(client, raw_client):
    ag = _make_agent(client, "revoked-bot")
    tok = client.post(f"/api/agents/{ag['id']}/token", json={"ttl_minutes": 30}).json()["token"]
    client.delete(f"/api/agents/{ag['id']}")   # disable
    g = raw_client.post("/v1/messages",
                        json={"model": "claude-sonnet-4-6", "max_tokens": 16,
                              "messages": [{"role": "user", "content": "hello"}]},
                        headers={"x-api-key": tok})
    assert g.status_code == 401


def test_session_token_ttl_bounds(client):
    ag = _make_agent(client, "ttl-bot")
    assert client.post(f"/api/agents/{ag['id']}/token",
                       json={"ttl_minutes": 0}).status_code == 422
    assert client.post(f"/api/agents/{ag['id']}/token",
                       json={"ttl_minutes": 100000}).status_code == 422


def test_per_agent_rate_limit(client, raw_client):
    ag = _make_agent(client, "throttled-bot")
    assert client.patch(f"/api/agents/{ag['id']}",
                        json={"rate_limit": 2}).json()["rate_limit"] == 2
    tok = client.post(f"/api/agents/{ag['id']}/token", json={"ttl_minutes": 5}).json()["token"]
    payload = {"model": "claude-sonnet-4-6", "max_tokens": 16,
               "messages": [{"role": "user", "content": "hi"}]}
    codes = [raw_client.post("/v1/messages", json=payload,
                             headers={"x-api-key": tok}).status_code for _ in range(3)]
    assert codes[:2] == [200, 200] and codes[2] == 429


def test_per_agent_block_severity_is_stricter_only(client, monkeypatch):
    from app import gateway
    from app.gateway import Principal, _effective_policy
    from app.database import get_db
    from app.main import app as _app
    ag = _make_agent(client, "strict-bot")
    client.patch(f"/api/agents/{ag['id']}", json={"block_severity": "low"})
    # Pull a db session from the overridden dependency to evaluate policy directly.
    gen = _app.dependency_overrides[get_db]()
    db = next(gen)
    try:
        agent_row_id = ag["id"]
        pol = _effective_policy(Principal(tenant_id=1, actor="x", agent="strict-bot",
                                          agent_id=agent_row_id), db)
        assert pol.block_severity == "low"       # agent tightened the tenant default (high)
        client.patch(f"/api/agents/{agent_row_id}", json={"block_severity": "critical"})
        pol = _effective_policy(Principal(tenant_id=1, actor="x", agent="strict-bot",
                                          agent_id=agent_row_id), db)
        assert pol.block_severity == "high"      # looser override ignored — stricter wins
    finally:
        gen.close()
