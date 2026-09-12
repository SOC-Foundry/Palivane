"""Agent identity attestation on tool calls (2b): when a tenant configures workload-identity
OIDC, a tool call by a named agent that isn't OIDC-attested (a bearer ag_ token, or none) is
flagged; with enforcement on, it's hard-blocked. No OIDC configured → no attestation flag."""

from __future__ import annotations


def _agent_token(client, name="researcher"):
    return client.post("/api/agents", json={"name": name}).json()["token"]


def _mcp(raw_client, tok, **over):
    body = {"method": "tools/call", "server": "fs", "tool": "read_file",
            "args_text": "path=/tmp/notes.txt", **over}
    return raw_client.post("/api/ingest/mcp", json=body,
                           headers={"X-Palivane-Token": tok}).json()


def _checks(r):
    return {s.get("check") for s in r.get("signals", [])}


def test_no_flag_when_oidc_not_configured(client, raw_client):
    # Attestation isn't expected unless the tenant turned on agent OIDC.
    tok = _agent_token(client)
    r = _mcp(raw_client, tok)
    assert "agent_attestation" not in _checks(r)


def test_unattested_tool_call_is_flagged_not_blocked(client, raw_client):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example.com"})
    tok = _agent_token(client)                       # ag_ bearer = 'token', not 'oidc'
    r = _mcp(raw_client, tok)
    assert "agent_attestation" in _checks(r)
    assert r["action"] != "block"                    # flag only — enforcement is off


def test_enforce_blocks_unattested_tool_call(client, raw_client):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example.com",
                                      "agent_attestation_enforce": True})
    tok = _agent_token(client)
    r = _mcp(raw_client, tok)
    assert "agent_attestation" in _checks(r)
    assert r["action"] == "block"


def test_enforce_setting_round_trips(client):
    r = client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example.com",
                                          "agent_attestation_enforce": True})
    assert r.status_code == 200
    assert r.json().get("agent_attestation_enforce") is True
