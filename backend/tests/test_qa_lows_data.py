"""Low-severity fixes from the deep QA: capture, policy and data."""

from __future__ import annotations

import httpx
import pytest

from app.models import Finding, Tenant


def _acme(db):
    return db.query(Tenant).filter(Tenant.slug == "acme").one()


# --- capture -------------------------------------------------------------------------------

def test_unreachable_provider_is_a_502_not_a_500(client, monkeypatch):
    from app import gateway

    def down(*a, **k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://api.example", "k"))
    monkeypatch.setattr(gateway, "_post_upstream_raw", down)
    monkeypatch.setattr(gateway, "_post_upstream_anthropic", down)
    r = client.post("/v1/messages", json={"model": "claude-x", "max_tokens": 8,
                                          "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 502, r.text
    assert r.json()["error"]["type"] == "upstream_unavailable"
    assert "model provider" in r.json()["error"]["message"]


# --- policy --------------------------------------------------------------------------------

def test_turning_off_prompt_injection_silences_its_ml_signal():
    from app.detectors.base import Category, Signal
    from app.policies import checks_signal_filter

    def sig(cat, check=""):
        return Signal(category=cat, title="t", detail="d", weight=0.5, confidence=0.5,
                      detector="x", check=check)

    keep = checks_signal_filter({"prompt_injection"})(
        [sig(Category.PROMPT_INJECTION, "prompt_injection_ml"),
         sig(Category.PROMPT_INJECTION),
         sig(Category.PROMPT_INJECTION, "hidden_characters"),      # a catalog check of its own
         sig(Category.SECRET_LEAK)])
    assert [(s.category.value, s.check) for s in keep] == [
        ("prompt_injection", "hidden_characters"), ("secret_leak", "")]


def test_tool_suppress_rejects_unknown_categories(client):
    r = client.patch("/api/tenant", json={"tool_suppress": "cursor:secret_leek"})
    assert r.status_code == 400 and "secret_leek" in r.json()["detail"]
    assert client.patch("/api/tenant",
                        json={"tool_suppress": "cursor:secret_leak,pii_exposure"}).status_code == 200


@pytest.mark.parametrize("path", ["/api/findings?limit=-1", "/api/findings?limit=0",
                                  "/api/findings?limit=100000", "/api/audit?limit=-1",
                                  "/api/my/findings?limit=-1", "/api/audit/sessions?days=-5",
                                  "/api/export/findings?limit=-1"])
def test_unbounded_inputs_are_refused(client, path):
    assert client.get(path).status_code == 422


def test_coverage_window_is_bounded(client):
    ev = [{"actor": "a@acme.com", "destination": "chatgpt.com"}]
    r = client.post("/api/coverage/reconcile", json={"events": ev, "window_days": 10 ** 9})
    assert r.status_code == 422


def test_justify_tokens_are_single_use(client, db_factory):
    from app.main import _spend_once
    db = db_factory()
    try:
        tid = _acme(db).id
        assert _spend_once(db, tid, "justify:abc", None) is True
        assert _spend_once(db, tid, "justify:abc", None) is False
        assert _spend_once(db, tid, "justify:", None) is False        # minted without an id
    finally:
        db.close()


def test_findings_fold_whatever_the_senders_case(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "fold", "actor": ""}).json()["token"]
    ids = set()
    for who in ("Dev@acme.com", "dev@acme.com", "DEV@ACME.COM"):
        r = raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": key},
                            json={"content": "SSN 123-45-6789", "destination": "chatgpt.com",
                                  "user": who})
        ids.add(r.json()["finding_id"])
    assert len(ids) == 1


# --- data ----------------------------------------------------------------------------------

def test_tenant_export_covers_the_orgs_other_tables(client):
    client.post("/api/allowlist", json={"kind": "command",
                                        "pattern": "curl -s https://get.example.com/install.sh | sh",
                                        "reason": "our installer"})
    doc = client.get("/api/export/tenant").json()
    for k in ("allowlist", "exception_requests", "saas_connectors", "sensor_heartbeats",
              "domains", "join_requests", "upgrade_requests"):
        assert k in doc and k in doc["counts"], k
    assert doc["counts"]["allowlist"] == 1
    assert "ml_corpus" not in doc                                  # content only on request
    assert "ml_corpus" in client.get("/api/export/tenant?include_content=true").json()


def test_extension_token_respects_the_key_quota(client, db_factory):
    client.post("/api/apikeys", json={"label": "one", "scope": "ingest"})   # quota 0 = no limit
    db = db_factory()
    from app.models import ApiKey
    t = _acme(db)
    t.quota_api_keys = db.query(ApiKey).filter(ApiKey.tenant_id == t.id,
                                               ApiKey.active.is_(True)).count()
    db.commit(); db.close()
    r = client.post("/api/extension/token?device=laptop-9")
    assert r.status_code == 403 and "quota" in r.json()["detail"]


@pytest.mark.parametrize("field,value", [("agent_oidc_issuer", "http://idp.example.com"),
                                         ("agent_oidc_jwks", "https://169.254.169.254/jwks"),
                                         ("agent_oidc_issuer", "https://127.0.0.1")])
def test_agent_oidc_urls_are_checked_when_saved(client, field, value):
    assert client.patch("/api/tenant", json={field: value}).status_code == 400
    assert client.patch("/api/tenant", json={field: "https://idp.example.com"}).status_code == 200
