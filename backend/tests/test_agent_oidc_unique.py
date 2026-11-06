"""Workload-identity tokens map to exactly one org (security review M3). Issuers are shared
(GitHub Actions has one for everyone), so the audience separates orgs: a duplicate
issuer+audience is refused at save, and at sign-in the token belongs to the one org with an
agent for its subject. Inert values."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as m
from app import oidc
from app.database import Base
from app.models import Agent, Tenant

ISS = "https://issuer.example"


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    monkeypatch.setattr("app.security.jwt_unverified_claims", lambda tok: {"iss": ISS})
    yield s
    s.close()


def _tenant(db, slug, aud):
    t = Tenant(slug=slug, name=slug, agent_oidc_issuer=ISS, agent_oidc_audience=aud)
    db.add(t)
    db.commit()
    return t


def _agent(db, t, subject):
    a = Agent(tenant_id=t.id, name=f"{t.slug}-agent", oidc_subject=subject, active=True)
    db.add(a)
    db.commit()
    return a


def _accepts(monkeypatch, audiences, sub="repo:acme/app"):
    def validate(iss, aud, token, jwks_uri=""):
        if aud not in audiences:
            raise oidc.OIDCError("audience mismatch")
        return {"sub": sub}
    monkeypatch.setattr(oidc, "validate_agent_jwt", validate)


def test_a_later_org_with_the_agent_still_wins(db, monkeypatch):
    first = _tenant(db, "first", "aud-shared-a")
    second = _tenant(db, "second", "aud-shared-b")
    mine = _agent(db, second, "repo:acme/app")
    _accepts(monkeypatch, {"aud-shared-a", "aud-shared-b"})   # validates for both orgs
    assert m._resolve_agent_jwt("tok", db).id == mine.id
    assert first.id < second.id


def test_two_orgs_claiming_the_token_is_refused(db, monkeypatch):
    a, b = _tenant(db, "a", "aud-1"), _tenant(db, "b", "aud-2")
    _agent(db, a, "repo:acme/app")
    _agent(db, b, "repo:acme/app")
    _accepts(monkeypatch, {"aud-1", "aud-2"})
    with pytest.raises(HTTPException) as e:
        m._resolve_agent_jwt("tok", db)
    assert "more than one org" in e.value.detail


def test_valid_token_without_an_agent_is_unattributed(db, monkeypatch):
    _tenant(db, "a", "aud-1")
    _accepts(monkeypatch, {"aud-1"})
    assert m._resolve_agent_jwt("tok", db) is None


def test_no_audience_validates_is_rejected(db, monkeypatch):
    _tenant(db, "a", "aud-1")
    _accepts(monkeypatch, set())
    with pytest.raises(HTTPException):
        m._resolve_agent_jwt("tok", db)


def test_settings_refuse_another_orgs_issuer_and_audience(client, db_factory):
    s = db_factory()
    s.add(Tenant(slug="other-org", name="Other", agent_oidc_issuer=ISS, agent_oidc_audience="taken"))
    s.commit()
    s.close()
    body = {"agent_oidc_issuer": ISS, "agent_oidc_audience": "taken"}
    r = client.patch("/api/tenant", json=body)
    assert r.status_code == 409, r.text
    body["agent_oidc_audience"] = "mine-only"
    assert client.patch("/api/tenant", json=body).status_code == 200
