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
    # The MDM policy pack (Jamf/Intune/GPO) stays gated on the Team plan.
    assert free_client.get("/api/policy-pack").status_code == 402


def test_free_plan_can_provision_device_installers(free_client):
    # Self-serve device installers (device_setup) are free so any org can seamlessly
    # onboard its whole fleet — only the MDM policy pack above is paid.
    r = free_client.post("/api/provision", json={"platform": "macos", "base_url": "https://w.io"})
    assert r.status_code == 200, r.text
    assert "macos" in r.json()["scripts"]


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
    # Team/enterprise have no plan defaults — fall through to the PALIVANE_QUOTA_* global.
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
    assert "sales@palivane.io" in r.json()["detail"]


def test_tenant_dict_exposes_plan(client):
    t = client.get("/api/auth/me").json()["tenant"]
    assert t["plan"] == "enterprise"
    assert "sso" in t["plan_features"]


def test_plan_helpers():
    assert plan_of(None) == "free"
    assert plan_of(Tenant(slug="x", plan="weird")) == "free"
    assert has_feature(Tenant(slug="x", plan="enterprise"), "sso")
    assert not has_feature(Tenant(slug="x", plan="team"), "sso")
    assert features_of(Tenant(slug="x", plan="team")) == ["alerts", "device_setup", "mdm"]


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


def test_plan_catalog_endpoint(client):
    cat = client.get("/api/plans").json()
    assert cat["current"] == "enterprise"   # conftest acme tenant
    keys = {f["key"] for f in cat["features"]}
    assert {"sso", "siem", "mdm", "alerts", "device_setup", "s3_delivery"} <= keys
    tiers = {t["name"]: t for t in cat["tiers"]}
    # The table lists what you can buy; trial/expired/self-hosted-free are states, not
    # products, so they only appear when they're the caller's own current tier.
    assert set(tiers) == {"team", "enterprise"}
    assert all(t["purchasable"] for t in cat["tiers"])
    assert tiers["team"]["includes"]["mdm"] is True
    assert tiers["team"]["includes"]["sso"] is False
    assert tiers["enterprise"]["includes"]["sso"] is True


def test_admin_plans_roster_requires_metrics_token(client, raw_client, monkeypatch):
    from app import main
    monkeypatch.setattr(main.settings, "metrics_token", "")
    assert raw_client.get("/api/admin/plans").status_code == 404
    monkeypatch.setattr(main.settings, "metrics_token", "s3cret-metrics")
    assert raw_client.get("/api/admin/plans").status_code == 401
    assert client.get("/api/admin/plans").status_code == 401   # tenant JWT not sufficient
    ok = raw_client.get("/api/admin/plans", headers={"Authorization": "Bearer s3cret-metrics"})
    assert ok.status_code == 200
    body = ok.json()
    assert "totals" in body and any(t["slug"] == "acme" for t in body["tenants"])


# --- hosted trial: full features for 14 days, then a loud (not silent) downgrade --------

def _tenant(db_factory, slug, plan, days=None):
    from datetime import datetime, timedelta, timezone
    from app.models import Tenant
    db = db_factory()
    t = Tenant(slug=slug, name=slug, plan=plan)
    if days is not None:
        t.trial_ends_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=days)
    db.add(t); db.commit(); db.refresh(t)
    db.close()
    return t


def test_signup_starts_a_trial(raw_client, db_factory, monkeypatch):
    from app import auth
    monkeypatch.setattr(auth.settings, "allow_signup", True)
    monkeypatch.setattr(auth.settings, "trial_days", 14)
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Trial Co", "slug": "trialco",
        "email": "boss@trialco.example", "password": "hunter2hunter2"})
    assert r.status_code in (200, 201)
    from app.models import Tenant
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "trialco").one()
    assert t.plan == "trial" and t.trial_ends_at is not None
    from app.plans import plan_of, trial_days_left
    assert plan_of(t) == "trial"
    assert 13 <= trial_days_left(t) <= 14
    db.close()


def test_trial_has_every_feature(db_factory):
    from app.plans import has_feature
    t = _tenant(db_factory, "livetrial", "trial", days=7)
    for f in ("alerts", "mdm", "sso", "siem", "s3_delivery", "judge", "device_setup"):
        assert has_feature(t, f), f


def test_expired_trial_loses_gated_features_but_keeps_reporting(db_factory):
    from app.plans import has_feature, plan_of, plan_quota, trial_days_left
    t = _tenant(db_factory, "deadtrial", "trial", days=-1)
    assert plan_of(t) == "expired"
    assert trial_days_left(t) == 0
    for f in ("alerts", "mdm", "sso", "siem", "s3_delivery", "judge", "device_setup"):
        assert not has_feature(t, f), f
    # Quotas tighten rather than going to zero: an expired trial must not silently stop
    # protecting a fleet that is still pointed at it.
    assert plan_quota(t, "ingest_per_day") > 0
    assert plan_quota(t, "users") > 0


def test_expired_trial_gets_its_own_upgrade_message(db_factory):
    import pytest
    from fastapi import HTTPException
    from app.plans import require_feature
    t = _tenant(db_factory, "deadtrial2", "trial", days=-1)
    with pytest.raises(HTTPException) as e:
        require_feature(t, "sso")
    assert e.value.status_code == 402
    assert "trial has ended" in e.value.detail


def test_upgrade_pointer_never_names_the_trial(db_factory):
    import pytest
    from fastapi import HTTPException
    from app.plans import require_feature
    # A self-hosted free tenant asking for a paid feature must be pointed at a plan it can
    # actually buy — not at "Trial", which holds every feature by construction.
    t = _tenant(db_factory, "selfhost", "free")
    for feature, expect in (("alerts", "Team"), ("sso", "Enterprise")):
        with pytest.raises(HTTPException) as e:
            require_feature(t, feature)
        assert expect in e.value.detail
        assert "Trial" not in e.value.detail


def test_trial_without_end_date_never_expires(db_factory):
    from app.plans import has_feature, plan_of
    t = _tenant(db_factory, "opentrial", "trial")     # operator cleared the clock
    assert plan_of(t) == "trial" and has_feature(t, "sso")


def test_self_hosted_free_is_untouched_by_the_trial_model(db_factory):
    from app.plans import has_feature, plan_of
    t = _tenant(db_factory, "shfree", "free")
    assert plan_of(t) == "free"
    assert has_feature(t, "device_setup") is True     # still fully usable
    assert has_feature(t, "mdm") is False


def test_catalog_shows_the_callers_own_tier_alongside_what_they_can_buy(db_factory):
    from app.plans import catalog
    t = _tenant(db_factory, "trialcat", "trial", days=3)
    tiers = {x["name"]: x for x in catalog(t)["tiers"]}
    assert set(tiers) == {"trial", "team", "enterprise"}
    assert tiers["trial"]["purchasable"] is False
    assert tiers["team"]["purchasable"] is True


def test_tenant_patch_reports_ignored_unknown_fields(client):
    """A misspelled setting must not read as applied.

    pydantic drops unknown keys by default, so PATCH /api/tenant returned 200 having changed
    nothing and the caller believed it had worked — the same lookup-miss-as-success shape that
    hid retired fleet clients and empty Actions variables. Unknown keys are now reported.
    """
    r = client.patch("/api/tenant", json={"name": "Acme", "alert_min_severty": "critical"})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Acme"                       # the real field still applied
    assert body["ignored_fields"] == ["alert_min_severty"]
    # A clean request must not grow the key at all.
    r2 = client.patch("/api/tenant", json={"name": "Acme2"})
    assert r2.status_code == 200 and "ignored_fields" not in r2.json()
    # A wrong TYPE on a known field is still a hard 422, not a silent ignore.
    assert client.patch("/api/tenant", json={"store_content": True}).status_code == 422
