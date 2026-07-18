"""Licensing plans: feature gates (402 + upgrade pointer), plan-default quotas, CLI."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import users as users_cli
from app.main import app
from app.metering import effective_quota
from app.models import Tenant
from app.plans import PLANS, features_of, has_feature, plan_of


def _plan_client(db_factory, plan: str, slug: str) -> TestClient:
    db = db_factory()
    users_cli.create_tenant(db, slug, slug.title(), plan=plan)
    users_cli.create_user(db, slug, f"admin@{slug}.com", "password123", "admin")
    db.close()
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": f"admin@{slug}.com", "password": "password123"})
    c.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})
    return c


@pytest.fixture
def free_client(db_factory):
    return _plan_client(db_factory, "free", "freeco")


@pytest.fixture
def team_client(db_factory):
    return _plan_client(db_factory, "team", "teamco")


def test_free_plan_gates_sso_siem_s3_alerts_mdm(free_client):
    assert free_client.put("/api/oidc", json={"issuer": "https://idp.example.com",
                                              "client_id": "x", "client_secret": "y"}).status_code == 402
    assert free_client.put("/api/saml", json={"idp_entity_id": "e", "idp_sso_url": "https://idp/sso",
                                              "idp_x509_cert": "c"}).status_code == 402
    assert free_client.patch("/api/tenant", json={"siem_url": "https://hec.example.com"}).status_code == 402
    assert free_client.patch("/api/tenant", json={"siem_s3_bucket": "b"}).status_code == 402
    r = free_client.patch("/api/tenant", json={"alert_webhook": "https://hooks.example.com/x"})
    assert r.status_code == 402 and "plan" in r.json()["detail"]
    assert free_client.get("/api/policy-pack").status_code == 402
    assert free_client.post("/api/provision", json={"platform": "macos",
                                                    "base_url": "https://w.io"}).status_code == 402


def test_free_plan_can_clear_gated_config(free_client):
    # Clearing (empty value) is never gated — an org downgraded with leftover config can
    # always turn it off.
    assert free_client.patch("/api/tenant", json={"alert_webhook": "", "siem_url": ""}).status_code == 200


def test_team_plan_gets_alerts_and_mdm_but_not_sso_siem(team_client):
    assert team_client.patch("/api/tenant",
                             json={"alert_webhook": "https://hooks.example.com/x"}).status_code == 200
    assert team_client.get("/api/policy-pack").status_code == 200
    assert team_client.put("/api/saml", json={"idp_entity_id": "e", "idp_sso_url": "https://idp/sso",
                                              "idp_x509_cert": "c"}).status_code == 402
    assert team_client.patch("/api/tenant", json={"siem_url": "https://hec.example.com"}).status_code == 402


def test_enterprise_fixture_passes_gates(client):
    # The conftest 'acme' tenant is Enterprise: gated features configure normally.
    assert client.patch("/api/tenant", json={"siem_url": "https://hec.example.com"}).status_code == 200
    assert client.get("/api/policy-pack").status_code == 200


def test_plan_default_quotas_and_precedence():
    free = Tenant(slug="f", plan="free")
    assert effective_quota(free, "users") == PLANS["free"]["quotas"]["users"]
    # A tenant override column beats the plan default.
    free.quota_users = 50
    assert effective_quota(free, "users") == 50
    # Team/enterprise have no plan defaults — fall through to the WARDEN_QUOTA_* global.
    from app.config import settings
    assert effective_quota(Tenant(slug="t", plan="team"), "users") == settings.quota_users


def test_free_plan_user_quota_enforced(free_client):
    for i in range(4):   # admin is #1; 5 total allowed on Free
        r = free_client.post("/api/users", json={"email": f"u{i}@freeco.com",
                                                 "password": "password123", "role": "analyst"})
        assert r.status_code == 200, r.text
    r = free_client.post("/api/users", json={"email": "u5@freeco.com",
                                             "password": "password123", "role": "analyst"})
    assert r.status_code == 403 and "quota" in r.json()["detail"]
    assert "/pricing" in r.json()["detail"]


def test_tenant_dict_exposes_plan(client):
    t = client.get("/api/auth/me").json()["tenant"]
    assert t["plan"] == "enterprise"
    assert "sso" in t["plan_features"]


def test_plan_helpers():
    assert plan_of(None) == "free"
    assert plan_of(Tenant(slug="x", plan="weird")) == "free"
    assert has_feature(Tenant(slug="x", plan="enterprise"), "sso")
    assert not has_feature(Tenant(slug="x", plan="team"), "sso")
    assert features_of(Tenant(slug="x", plan="team")) == ["alerts", "mdm"]


def test_cli_set_plan(db_factory, monkeypatch):
    db = db_factory()
    users_cli.create_tenant(db, "corp", "Corp")
    eng = db.get_bind()
    db.close()
    # Point the CLI at the test DB (both the session factory and the create_all engine).
    monkeypatch.setattr(users_cli, "SessionLocal", db_factory)
    monkeypatch.setattr(users_cli, "db_engine", eng)
    assert users_cli.main(["set-plan", "--tenant", "corp", "--plan", "team"]) == 0
    db = db_factory()
    assert db.query(Tenant).filter(Tenant.slug == "corp").first().plan == "team"
    db.close()
