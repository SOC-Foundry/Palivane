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
                                      "agent_oidc_audience": "palivane"})
    client.post("/api/agents", json={"name": "wl-bot", "oidc_subject": "spn-billing"})
    # Trust the JWKS boundary; validate the mapping logic.
    monkeypatch.setattr(oidc, "validate_agent_jwt",
                        lambda iss, aud, token, jwks_uri="": {"iss": iss, "aud": aud, "sub": "spn-billing"})
    tok = _jwt({"iss": "https://idp.example", "aud": "palivane", "sub": "spn-billing"})

    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "SSN 123-45-6789", "destination": "https://chatgpt.com/"},
                        headers={"X-Palivane-Token": tok})
    assert r.status_code == 200
    findings = client.get("/api/findings").json()["findings"]
    assert any(f.get("agent") == "wl-bot" for f in findings)


def test_unknown_issuer_rejected(raw_client):
    tok = _jwt({"iss": "https://evil.example", "sub": "x"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": tok})
    assert r.status_code == 401


def test_issuer_without_audience_rejected(client, raw_client):
    # An issuer configured with no audience can't authenticate agents (fail closed):
    # otherwise any validly-signed token from that issuer would be accepted.
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example"})
    tok = _jwt({"iss": "https://idp.example", "sub": "x"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": tok})
    assert r.status_code == 401


def test_invalid_signature_rejected(client, raw_client, monkeypatch):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example",
                                      "agent_oidc_audience": "palivane"})
    client.post("/api/agents", json={"name": "wl2", "oidc_subject": "spn-2"})

    def _boom(*a, **k):
        raise oidc.OIDCError("bad signature")
    monkeypatch.setattr(oidc, "validate_agent_jwt", _boom)
    tok = _jwt({"iss": "https://idp.example", "aud": "palivane", "sub": "spn-2"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": tok})
    assert r.status_code == 401


def test_valid_jwt_but_no_matching_agent(client, raw_client, monkeypatch):
    client.patch("/api/tenant", json={"agent_oidc_issuer": "https://idp.example",
                                      "agent_oidc_audience": "palivane"})
    monkeypatch.setattr(oidc, "validate_agent_jwt",
                        lambda iss, aud, token, jwks_uri="": {"iss": iss, "sub": "nobody"})
    tok = _jwt({"iss": "https://idp.example", "aud": "palivane", "sub": "nobody"})
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": tok})
    assert r.status_code == 401   # audience validated, but no agent maps to that subject


def test_shared_issuer_resolves_by_audience(client, raw_client, db_factory, monkeypatch):
    """Two tenants on the SAME issuer (e.g. GitHub Actions' shared issuer) must be told
    apart by the audience the token validates against — not by whichever row sorts first."""
    from app import users as users_cli
    from fastapi.testclient import TestClient
    from app.main import app
    ISS = "https://token.actions.githubusercontent.com"

    # Tenant A (acme): audience aud-a, agent spn-a.
    client.patch("/api/tenant", json={"agent_oidc_issuer": ISS, "agent_oidc_audience": "aud-a"})
    client.post("/api/agents", json={"name": "a-bot", "oidc_subject": "spn-a"})

    # Tenant B (beta): same issuer, audience aud-b, agent spn-b.
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta")
    users_cli.create_user(db, "beta", "admin@beta.com", "password123", "admin")
    db.close()
    c2 = TestClient(app)
    tok2 = c2.post("/api/auth/login", json={"email": "admin@beta.com", "password": "password123"}).json()["access_token"]
    c2.headers.update({"Authorization": f"Bearer {tok2}"})
    c2.patch("/api/tenant", json={"agent_oidc_issuer": ISS, "agent_oidc_audience": "aud-b"})
    c2.post("/api/agents", json={"name": "b-bot", "oidc_subject": "spn-b"})

    # Real audience validation: only the tenant whose audience matches the token validates.
    def fake_validate(iss, aud, token, jwks_uri=""):
        claims = jwt_unverified_claims(token)
        if claims.get("aud") != aud:
            raise oidc.OIDCError("audience mismatch")
        return claims
    monkeypatch.setattr(oidc, "validate_agent_jwt", fake_validate)

    # A token minted for B (aud-b, spn-b) must attribute to B's agent, not A's.
    tok = _jwt({"iss": ISS, "aud": "aud-b", "sub": "spn-b"})
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "SSN 123-45-6789", "destination": "https://chatgpt.com/"},
                        headers={"X-Palivane-Token": tok})
    assert r.status_code == 200
    # It landed in B's tenant, attributed to b-bot — and NOT in A's findings.
    assert any(f.get("agent") == "b-bot" for f in c2.get("/api/findings").json()["findings"])
    assert not any(f.get("agent") == "b-bot" for f in client.get("/api/findings").json()["findings"])
