"""A tenant's gateway upstream config must never carry the platform's credentials to a host
the tenant chose: no global key on a tenant base_url, no host injection through a cloud
region, no platform default credentials for a tenant cloud config, no cross-tenant token
cache hits. Values here are inert placeholders."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app import upstreams
from app.config import settings

PLATFORM_KEY = "platform-" + "placeholder-value"
TENANT_KEY = "tenant-" + "placeholder-value"


class _Q:
    def __init__(self, rows, provider=None):
        self.rows, self.provider = rows, provider

    def filter(self, *conds):
        # the provider is the second filter condition's right-hand value
        prov = conds[1].right.value if len(conds) > 1 else None
        return _Q(self.rows, prov)

    def first(self):
        return self.rows.get(self.provider)


class FakeDB:
    def __init__(self, rows):
        self.rows = rows

    def query(self, _model):
        return _Q(self.rows)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(settings, "gateway_anthropic_base", "https://api.anthropic.com")
    monkeypatch.setattr(settings, "gateway_anthropic_key", PLATFORM_KEY)
    monkeypatch.setattr(settings, "gateway_vertex_project", "")
    monkeypatch.setattr(settings, "gateway_bedrock_region", "")
    monkeypatch.setattr(settings, "gateway_bedrock_key", "")
    # secrets are stored sealed; the fake rows carry them in the clear
    monkeypatch.setattr("app.crypto.unseal_secret", lambda blob, dek: blob)
    monkeypatch.setattr("app.crypto.dek_for", lambda db, tid: b"x")
    monkeypatch.setattr("app.netguard.is_safe_url", lambda url: True)


def row(base="", key=""):
    return SimpleNamespace(base_url=base, key_encrypted=key)


def test_tenant_base_url_never_gets_the_platform_key(env):
    db = FakeDB({"anthropic": row(base="https://tenant-host.example")})
    base, key = upstreams.resolve("anthropic", 7, db)
    assert base == "https://tenant-host.example" and key == ""
    # and with no key the Anthropic flavor doesn't resolve to the tenant host at all
    assert upstreams.resolve_anthropic_upstream(7, db) is None


def test_tenant_base_url_with_own_key_is_fine(env):
    db = FakeDB({"anthropic": row(base="https://tenant-host.example", key=TENANT_KEY)})
    assert upstreams.resolve("anthropic", 7, db) == ("https://tenant-host.example", TENANT_KEY)


def test_tenant_key_on_platform_base_is_fine(env):
    db = FakeDB({"anthropic": row(key=TENANT_KEY)})
    assert upstreams.resolve("anthropic", 7, db) == ("https://api.anthropic.com", TENANT_KEY)


def test_no_tenant_row_uses_the_platform_pair(env):
    assert upstreams.resolve("anthropic", 7, FakeDB({})) == ("https://api.anthropic.com", PLATFORM_KEY)


def _sa(email="svc@tenant-proj.iam.gserviceaccount.com", token_uri="https://oauth2.googleapis.com/token"):
    return {"type": "service_account", "client_email": email, "private_key": "placeholder", "token_uri": token_uri}


@pytest.mark.parametrize("region", ["host.example/x#", "u@host.example/x#", "us-central1.host.example", "", None, "US-EAST-1"])
def test_vertex_region_cannot_rewrite_the_host(env, monkeypatch, region):
    monkeypatch.setattr(settings, "gateway_anthropic_key", "")
    blob = json.dumps({"project": "tenant-proj-1", "region": region, "service_account_json": _sa()})
    assert upstreams.tenant_cloud_config_error("vertex", blob)
    assert upstreams.resolve_anthropic_upstream(7, FakeDB({"vertex": row(key=blob)})) is None


def test_tenant_vertex_without_its_own_service_account_never_uses_platform_credentials(env, monkeypatch):
    monkeypatch.setattr(settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(settings, "gateway_vertex_project", "platform-proj-1")
    monkeypatch.setattr(settings, "gateway_vertex_region", "us-east5")
    blob = json.dumps({"project": "tenant-proj-1", "region": "us-east5"})
    assert upstreams.tenant_cloud_config_error("vertex", blob)
    # the tenant configured Vertex, so it does not silently fall back to the platform's
    assert upstreams.resolve_anthropic_upstream(7, FakeDB({"vertex": row(key=blob)})) is None


def test_service_account_token_uri_must_be_google(env, monkeypatch):
    monkeypatch.setattr(settings, "gateway_anthropic_key", "")
    blob = json.dumps({"project": "tenant-proj-1", "region": "us-east5",
                       "service_account_json": _sa(token_uri="https://host.example/token")})
    assert upstreams.tenant_cloud_config_error("vertex", blob)


def test_valid_tenant_vertex_config_resolves_to_its_own_terms(env, monkeypatch):
    monkeypatch.setattr(settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(settings, "gateway_vertex_project", "platform-proj-1")
    blob = json.dumps({"project": "tenant-proj-1", "region": "europe-west4", "service_account_json": _sa()})
    up = upstreams.resolve_anthropic_upstream(7, FakeDB({"vertex": row(key=blob)}))
    assert up["flavor"] == "vertex" and up["project"] == "tenant-proj-1" and up["region"] == "europe-west4"
    assert up["sa_json"]["client_email"].endswith("tenant-proj.iam.gserviceaccount.com")


def test_platform_vertex_config_still_uses_default_credentials(env, monkeypatch):
    monkeypatch.setattr(settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(settings, "gateway_vertex_project", "platform-proj-1")
    monkeypatch.setattr(settings, "gateway_vertex_region", "us-east5")
    up = upstreams.resolve_anthropic_upstream(7, FakeDB({}))
    assert up == {"flavor": "vertex", "project": "platform-proj-1", "region": "us-east5", "sa_json": None}


def test_tenant_bedrock_needs_its_own_key_and_a_clean_region(env, monkeypatch):
    monkeypatch.setattr(settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(settings, "gateway_bedrock_region", "us-east-1")
    monkeypatch.setattr(settings, "gateway_bedrock_key", PLATFORM_KEY)
    for blob in (json.dumps({"region": "us-east-1"}),                       # no own key: no ambient chain
                 json.dumps({"region": "host.example/x#", "key": TENANT_KEY})):
        assert upstreams.tenant_cloud_config_error("bedrock", blob)
        assert upstreams.resolve_anthropic_upstream(7, FakeDB({"bedrock": row(key=blob)})) is None
    good = json.dumps({"region": "us-west-2", "key": TENANT_KEY})
    assert upstreams.resolve_anthropic_upstream(7, FakeDB({"bedrock": row(key=good)})) == \
        {"flavor": "bedrock", "region": "us-west-2", "key": TENANT_KEY}


def test_vertex_token_cache_is_keyed_by_the_whole_credential(monkeypatch):
    issued = []

    class Creds:
        def __init__(self, info):
            self.token = "tok-for-" + info["private_key"]

        def refresh(self, _req):
            issued.append(self.token)

    monkeypatch.setattr("google.oauth2.service_account.Credentials.from_service_account_info",
                        lambda info, scopes: Creds(info))
    upstreams._VTOK_CACHE.clear()
    a = dict(_sa(), private_key="tenant-a")
    b = dict(_sa(), private_key="tenant-b")          # same client_email, different key material
    assert upstreams.vertex_token(a) == "tok-for-tenant-a"
    assert upstreams.vertex_token(b) == "tok-for-tenant-b"   # not served tenant A's cached token
    assert issued == ["tok-for-tenant-a", "tok-for-tenant-b"]
    upstreams._VTOK_CACHE.clear()
