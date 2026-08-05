"""Regression tests for the post-audit hardening fixes (agent JWT audience, oidc_subject
uniqueness, policy-override audit + lowercasing, input caps)."""

from __future__ import annotations

import base64
import json

import app.oidc as oidc


def _jwt(claims: dict) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


def test_agent_jwt_rejected_without_configured_audience(client, raw_client, monkeypatch):
    # Issuer configured, NO audience -> must fail closed (cross-tenant hole otherwise).
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example",
                                      "agent_oidc_audience": ""})
    client.post("/api/agents", json={"name": "no-aud-bot", "oidc_subject": "spn-x"})
    monkeypatch.setattr(oidc, "validate_agent_jwt", lambda *a, **k: {"sub": "spn-x"})  # would pass if reached
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": _jwt({"iss": "https://idp.example", "sub": "spn-x"})})
    assert r.status_code == 401


def test_duplicate_oidc_subject_rejected(client):
    client.post("/api/agents", json={"name": "a1", "oidc_subject": "spn-dup"})
    assert client.post("/api/agents", json={"name": "a2", "oidc_subject": "spn-dup"}).status_code == 409
    a3 = client.post("/api/agents", json={"name": "a3"}).json()["id"]
    assert client.patch(f"/api/agents/{a3}", json={"oidc_subject": "spn-dup"}).status_code == 409


def test_policy_override_is_audited(client):
    client.post("/api/policies/overrides", json={"scope": "group", "match": "*@svc.acme.com",
                                                 "disabled_checks": ["pii_exposure"]})
    assert "policy_override.upsert" in {e["action"] for e in client.get("/api/audit").json()["entries"]}
    oid = next(o["id"] for o in client.get("/api/policies").json()["overrides"])
    client.delete(f"/api/policies/overrides/{oid}")
    assert "policy_override.delete" in {e["action"] for e in client.get("/api/audit").json()["entries"]}


def test_override_match_stored_lowercase(client):
    client.post("/api/policies/overrides", json={"scope": "group", "match": "*@Contractors.ACME.com",
                                                 "disabled_checks": ["pii_exposure"]})
    assert any(o["match"] == "*@contractors.acme.com"
               for o in client.get("/api/policies").json()["overrides"])


def test_input_caps(client):
    r = client.post("/api/agent-roles", json={"name": "big", "allow_tools": [f"t{i}" for i in range(201)]})
    assert r.status_code == 422
    r = client.post("/api/discovery/ingest",
                    json={"events": [{"actor": "a", "destination": "chatgpt.com", "count": 0}]})
    assert r.status_code == 422


def test_finding_status_change_is_audited(client):
    client.post("/api/analyze", json={"content": "hi there", "persist": True})
    fid = client.get("/api/findings").json()["findings"][0]["id"]
    assert client.patch(f"/api/findings/{fid}", json={"status": "triaged"}).status_code == 200
    actions = [e["action"] for e in client.get("/api/audit").json()["entries"]]
    assert "finding.status" in actions
