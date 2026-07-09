"""Agent workload identity (Phase 3): OIDC/JWT agent auth + attribution."""

from __future__ import annotations

import base64
import json

import app.main as main
import app.oidc as oidc
from app.security import looks_like_jwt, jwt_unverified_claims


def _jwt(claims: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


def test_jwt_helpers():
    tok = _jwt({"iss": "https://idp.example", "sub": "spn-x"})
    assert looks_like_jwt(tok)
    assert not looks_like_jwt("ak_nope")
    assert jwt_unverified_claims(tok)["iss"] == "https://idp.example"


def test_agent_jwt_authenticates_and_attributes(client, raw_client, monkeypatch):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example",
                                      "agent_oidc_audience": "warden"})
    client.post("/api/agents", json={"name": "wl-bot", "oidc_subject": "spn-billing"})
    # Trust the JWKS boundary; validate the mapping logic.
    monkeypatch.setattr(oidc, "validate_agent_jwt",
                        lambda iss, aud, token, jwks_uri="": {"iss": iss, "aud": aud, "sub": "spn-billing"})
    tok = _jwt({"iss": "https://idp.example", "aud": "warden", "sub": "spn-billing"})

    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "SSN 123-45-6789", "destination": "https://chatgpt.com/"},
                        headers={"X-Warden-Token": tok})
    assert r.status_code == 200
    findings = client.get("/api/findings").json()["findings"]
    assert any(f.get("agent") == "wl-bot" for f in findings)


def test_unknown_issuer_rejected(raw_client):
    tok = _jwt({"iss": "https://evil.example", "sub": "x"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Warden-Token": tok})
    assert r.status_code == 401


def test_invalid_signature_rejected(client, raw_client, monkeypatch):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example"})
    client.post("/api/agents", json={"name": "wl2", "oidc_subject": "spn-2"})

    def _boom(*a, **k):
        raise oidc.OIDCError("bad signature")
    monkeypatch.setattr(oidc, "validate_agent_jwt", _boom)
    tok = _jwt({"iss": "https://idp.example", "sub": "spn-2"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Warden-Token": tok})
    assert r.status_code == 401


def test_valid_jwt_but_no_matching_agent(client, raw_client, monkeypatch):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example"})
    monkeypatch.setattr(oidc, "validate_agent_jwt",
                        lambda iss, aud, token, jwks_uri="": {"iss": iss, "sub": "nobody"})
    tok = _jwt({"iss": "https://idp.example", "sub": "nobody"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Warden-Token": tok})
    assert r.status_code == 401   # authenticated issuer, but no agent maps to that subject
