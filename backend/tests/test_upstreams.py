"""Per-tenant upstream provider config: encryption, resolver, admin API, and that the
gateway forwards with the tenant's own key (billing isolation for multi-tenant SaaS)."""

from __future__ import annotations

from app import gateway
from app import upstreams
from app.config import settings
from app.crypto import decrypt, encrypt
from app.models import TenantUpstream


def test_crypto_roundtrip_and_bad_token():
    assert decrypt(encrypt("sk-ant-secret")) == "sk-ant-secret"
    assert encrypt("") == "" and decrypt("") == ""
    assert decrypt("not-a-valid-token") == ""     # undecryptable → treated as unset


def test_resolve_prefers_tenant_over_global(db_factory, monkeypatch):
    from app import users as users_cli
    db = db_factory()
    tenant = users_cli.create_tenant(db, "acme", "Acme")
    monkeypatch.setattr(settings, "gateway_upstream_base", "https://global.example/v1")
    monkeypatch.setattr(settings, "gateway_upstream_key", "global-key")

    # No tenant row → global fallback.
    assert upstreams.resolve("openai", tenant.id, db) == ("https://global.example/v1", "global-key")

    # Tenant row overrides (key stored encrypted, resolved decrypted). Base is a public IP
    # literal so the call-time SSRF re-check passes without depending on DNS.
    db.add(TenantUpstream(tenant_id=tenant.id, provider="openai",
                          base_url="https://8.8.8.8/v1", key_encrypted=encrypt("acme-key")))
    db.commit()
    assert upstreams.resolve("openai", tenant.id, db) == ("https://8.8.8.8/v1", "acme-key")


def test_upstream_api_hides_key_and_validates_provider(client):
    r = client.put("/api/upstreams/anthropic", json={"base_url": "https://x.test", "key": "sk-secret"})
    assert r.status_code == 200
    body = r.json()
    assert body["key_set"] is True and body["effective"] == "tenant" and "key" not in body

    lst = client.get("/api/upstreams").json()["upstreams"]
    anth = next(u for u in lst if u["provider"] == "anthropic")
    assert anth["key_set"] and anth["base_url"] == "https://x.test" and "key" not in anth

    assert client.put("/api/upstreams/bogus", json={"base_url": "x"}).status_code == 404
    # Removing it falls back to the global default.
    assert client.delete("/api/upstreams/anthropic").json()["effective"] == "global"


def test_upstreams_require_auth(raw_client):
    assert raw_client.get("/api/upstreams").status_code == 401
    assert raw_client.put("/api/upstreams/openai", json={"base_url": "x"}).status_code == 401


def test_update_keeps_key_when_omitted(client):
    client.put("/api/upstreams/openai", json={"base_url": "https://a.test", "key": "sk-first"})
    # Change only base_url (no key in body) — key stays set.
    r = client.put("/api/upstreams/openai", json={"base_url": "https://b.test"})
    assert r.json()["key_set"] is True and r.json()["base_url"] == "https://b.test"


ANTHROPIC_BENIGN = {"model": "claude-sonnet-4-6", "max_tokens": 32,
                    "messages": [{"role": "user", "content": "Explain TCP vs UDP."}]}


def test_gateway_forwards_with_tenant_key(client, monkeypatch):
    """The tenant's own key + base URL are used for forwarding — not the global env."""
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    client.put("/api/upstreams/anthropic",
               json={"base_url": "https://8.8.8.8", "key": "sk-ant-acme"})   # public IP: passes SSRF re-check

    captured = {}

    class FakeResp:
        status_code = 200
        def json(self):
            return {"id": "msg_x", "type": "message", "role": "assistant",
                    "model": "claude-sonnet-4-6", "content": [{"type": "text", "text": "ok"}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, json=None, headers=None, **k):
            captured["url"] = url
            captured["headers"] = headers
            return FakeResp()

    monkeypatch.setattr(gateway.httpx, "Client", FakeClient)
    r = client.post("/v1/messages", json=ANTHROPIC_BENIGN)
    assert r.status_code == 200
    assert captured["url"].startswith("https://8.8.8.8")
    assert captured["headers"]["x-api-key"] == "sk-ant-acme"

GROK_BENIGN = {"model": "grok-3", "max_tokens": 32,
               "messages": [{"role": "user", "content": "Explain TCP vs UDP."}]}


def test_openai_shape_provider_routes_grok_to_xai():
    assert gateway._openai_shape_provider("grok-3") == "xai"
    assert gateway._openai_shape_provider("grok-code-fast-1") == "xai"
    assert gateway._openai_shape_provider("gpt-4o") == "openai"
    assert gateway._openai_shape_provider("") == "openai"


def test_resolve_xai_global_default(db_factory, monkeypatch):
    from app import users as users_cli
    db = db_factory()
    tenant = users_cli.create_tenant(db, "acme", "Acme")
    monkeypatch.setattr(settings, "gateway_xai_base", "https://api.x.ai/v1")
    monkeypatch.setattr(settings, "gateway_xai_key", "")
    assert upstreams.resolve("xai", tenant.id, db) == ("https://api.x.ai/v1", "")
    assert "xai" in upstreams.PROVIDERS


def test_grok_model_forwards_to_xai_upstream_not_openai(client, monkeypatch):
    """A grok-* model routed through /v1/chat/completions must forward to the tenant's xAI
    upstream, not its OpenAI one — otherwise Grok traffic would hit the wrong provider."""
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    # Distinct bases so the assertion proves which upstream was chosen (public IPs pass SSRF).
    client.put("/api/upstreams/openai", json={"base_url": "https://1.1.1.1/v1", "key": "sk-oai"})
    client.put("/api/upstreams/xai", json={"base_url": "https://8.8.8.8/v1", "key": "xai-acme"})

    captured = {}

    class FakeResp:
        status_code = 200
        def json(self):
            return {"id": "x", "object": "chat.completion", "model": "grok-3",
                    "choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, json=None, headers=None, **k):
            captured["url"] = url
            return FakeResp()

    monkeypatch.setattr(gateway.httpx, "Client", FakeClient)
    r = client.post("/v1/chat/completions", json=GROK_BENIGN)
    assert r.status_code == 200
    assert captured["url"].startswith("https://8.8.8.8")   # xAI upstream, not 1.1.1.1 (OpenAI)


def test_xai_upstream_api_accepts_provider(client):
    r = client.put("/api/upstreams/xai", json={"base_url": "https://8.8.8.8/v1", "key": "xai-k"})
    assert r.status_code == 200 and r.json()["key_set"] is True
    lst = client.get("/api/upstreams").json()["upstreams"]
    assert any(u["provider"] == "xai" for u in lst)


def test_resolve_ignores_internal_tenant_base(client, db_factory):
    # A stored tenant base_url that resolves internal (e.g. bypassing set-time via an old
    # row / rebind) must NOT be used by the gateway — resolve() re-checks at call time and
    # falls back to the trusted global default.
    from app import upstreams
    from app.models import Tenant, TenantUpstream
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    db.add(TenantUpstream(tenant_id=tid, provider="openai",
                          base_url="http://169.254.169.254/v1", key_encrypted=""))
    db.commit()
    base, _key = upstreams.resolve("openai", tid, db)
    assert base != "http://169.254.169.254/v1"   # internal base rejected -> global default
    db.close()
