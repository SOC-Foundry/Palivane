"""Auth / gateway hardening regressions: each test pins a hole that was open.

Gateway JWTs get the console's session checks, API keys die with their user, deactivation
revokes keys on every path, the client IP can't be forged, MCP OAuth grants are tenant-bound,
the operator surface takes its token from the header only, warehouse hosts go through the
SSRF guard, the guard itself allowlists globally-routable addresses, and a stale unverified
domain claim can't lock the real owner out forever.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import users as users_cli
from app.main import app
from app.models import ApiKey, OAuthToken, Tenant, TenantDomain, User
from app.security import create_token, hash_token

CHAT = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Name three cats."}]}


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin(db_factory) -> User:
    db = db_factory()
    u = db.query(User).filter(User.email == "admin@acme.com").one()
    db.expunge(u)
    db.close()
    return u


def _add_user(db_factory, email: str, role: str = "analyst", tenant: str = "acme") -> int:
    db = db_factory()
    u = users_cli.create_user(db, tenant, email, "password123", role)
    uid = u.id
    db.close()
    return uid


def _set(db_factory, model, row_id: int, **fields) -> None:
    db = db_factory()
    row = db.get(model, row_id)
    for k, v in fields.items():
        setattr(row, k, v)
    db.commit()
    db.close()


# --- 1. gateway JWTs: same checks as the console -----------------------------------------

def test_gateway_accepts_a_real_session_jwt(client, raw_client, db_factory):
    u = _admin(db_factory)
    tok = create_token({"sub": str(u.id), "tenant_id": u.tenant_id, "role": u.role, "tv": 0})
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(tok)).status_code != 401


@pytest.mark.parametrize("typ", ["mfa", "join", "pwreset", "email_verify", "oidc_state"])
def test_gateway_rejects_special_purpose_jwts(client, raw_client, db_factory, typ):
    """An MFA challenge (first factor only) or a join/reset token is not a session."""
    u = _admin(db_factory)
    tok = create_token({"typ": typ, "sub": str(u.id), "tv": 0}, ttl=300)
    r = raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(tok))
    assert r.status_code == 401, r.text


def test_gateway_rejects_a_revoked_session(client, raw_client, db_factory):
    """Logout-everywhere / password reset bump token_version; the gateway must honour it."""
    u = _admin(db_factory)
    tok = create_token({"sub": str(u.id), "tenant_id": u.tenant_id, "role": u.role, "tv": 0})
    _set(db_factory, User, u.id, token_version=1)
    r = raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(tok))
    assert r.status_code == 401 and "revoked" in r.text


def test_gateway_rejects_demo_sessions(client, raw_client, db_factory):
    u = _admin(db_factory)
    tok = create_token({"sub": str(u.id), "tenant_id": u.tenant_id, "role": u.role, "tv": 0,
                        "demo": True})
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(tok)).status_code == 403


def test_gateway_refuses_a_suspended_tenant(client, raw_client, db_factory):
    u = _admin(db_factory)
    tok = create_token({"sub": str(u.id), "tenant_id": u.tenant_id, "role": u.role, "tv": 0})
    _set(db_factory, Tenant, u.tenant_id, status="suspended")
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(tok)).status_code == 403


# --- 2. gateway API keys: live user, known scope ------------------------------------------

def _mint_key(client, **body) -> str:
    r = client.post("/api/apikeys", json={"label": "k", **body})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_capture_key_dies_with_its_actor(client, raw_client, db_factory):
    uid = _add_user(db_factory, "leaver@acme.com")
    token = _mint_key(client, actor="leaver@acme.com")
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(token)).status_code != 401
    _set(db_factory, User, uid, active=False)          # deactivated behind the API's back
    r = raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(token))
    assert r.status_code == 401 and "no longer active" in r.text
    # Same on the ingest plane, which shares the resolver.
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi", "destination": "chatgpt.com"},
                        headers={"X-Palivane-Token": token})
    assert r.status_code == 401


def test_console_key_dies_with_its_user(client, raw_client, db_factory):
    token = _mint_key(client, scope="console_read")
    admin = _admin(db_factory)
    other = _add_user(db_factory, "admin2@acme.com", role="admin")
    assert other
    _set(db_factory, User, admin.id, active=False)
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(token)).status_code == 401


def test_fleet_key_with_a_non_user_actor_still_works(client, raw_client):
    token = _mint_key(client, actor="svc@acme.com")     # no user by that email: unaffected
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(token)).status_code != 401


def test_unknown_scope_key_is_refused(client, raw_client, db_factory):
    token = _mint_key(client)
    db = db_factory()
    key = db.query(ApiKey).filter(ApiKey.prefix == token[:11]).one()
    key.scope = "something_else"
    db.commit()
    db.close()
    assert raw_client.post("/v1/chat/completions", json=CHAT, headers=_bearer(token)).status_code == 401


# --- 3. deactivation revokes keys on every path -------------------------------------------

def _active_keys(db_factory, email: str) -> int:
    db = db_factory()
    n = db.query(ApiKey).filter(ApiKey.actor == email, ApiKey.active.is_(True)).count()
    db.close()
    return n


def test_scim_deactivation_revokes_the_users_keys(client, db_factory):
    scim = client.post("/api/scim/token").json()["token"]
    uid = _add_user(db_factory, "bob@acme.com")
    _mint_key(client, actor="bob@acme.com")
    assert _active_keys(db_factory, "bob@acme.com") == 1
    r = client.patch(f"/scim/v2/Users/{uid}", headers=_bearer(scim),
                     json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                           "Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert r.status_code == 200, r.text
    assert _active_keys(db_factory, "bob@acme.com") == 0


def test_admin_deactivation_revokes_keys_and_sessions(client, raw_client, db_factory):
    uid = _add_user(db_factory, "carol@acme.com")
    _mint_key(client, actor="carol@acme.com")
    r = client.patch(f"/api/users/{uid}", json={"active": False})
    assert r.status_code == 200, r.text
    assert _active_keys(db_factory, "carol@acme.com") == 0
    db = db_factory()
    assert db.get(User, uid).token_version == 1
    db.close()


def test_deviceless_extension_connect_does_not_kill_other_machines(client, raw_client):
    """Two machines connecting without a device id used to share (and rotate) one key."""
    first = client.post("/api/extension/token").json()["token"]
    second = client.post("/api/extension/token").json()["token"]
    assert first != second
    for tok in (first, second):
        assert raw_client.get("/api/enroll/check", headers={"X-Palivane-Token": tok}).status_code == 200


# --- 5. client IP -------------------------------------------------------------------------

def _req(headers: dict, peer: str = "10.0.0.9") -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                    "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
                    "client": (peer, 1234)})


def test_client_ip_ignores_the_client_typed_xff_entry(monkeypatch):
    from app.auth import _client_ip, settings
    monkeypatch.setattr(settings, "client_ip_header", "")
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    # The left entry is whatever the client sent; Cloud Run appended the right one.
    assert _client_ip(_req({"X-Forwarded-For": "1.1.1.1, 203.0.113.7"})) == "203.0.113.7"
    assert _client_ip(_req({})) == "10.0.0.9"


def test_client_ip_hops_and_peer(monkeypatch):
    from app.auth import _client_ip, settings
    monkeypatch.setattr(settings, "client_ip_header", "")
    monkeypatch.setattr(settings, "trusted_proxy_hops", 2)
    assert _client_ip(_req({"X-Forwarded-For": "6.6.6.6, 203.0.113.7, 35.0.0.1"})) == "203.0.113.7"
    assert _client_ip(_req({"X-Forwarded-For": "203.0.113.7"})) == "10.0.0.9"   # too few hops
    monkeypatch.setattr(settings, "trusted_proxy_hops", 0)
    assert _client_ip(_req({"X-Forwarded-For": "6.6.6.6"})) == "10.0.0.9"


def test_client_ip_trusted_edge_header(monkeypatch):
    from app.auth import _client_ip, settings
    monkeypatch.setattr(settings, "client_ip_header", "x-palivane-client-ip")
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    r = _req({"X-Palivane-Client-IP": "198.51.100.4", "X-Forwarded-For": "1.1.1.1, 172.64.0.1"})
    assert _client_ip(r) == "198.51.100.4"
    # Header configured but absent: fall back to the XFF rule, not to the forged left entry.
    assert _client_ip(_req({"X-Forwarded-For": "1.1.1.1, 172.64.0.1"})) == "172.64.0.1"


def test_rotating_a_fake_xff_does_not_dodge_the_login_throttle(raw_client, db_factory, monkeypatch):
    from app.auth import settings
    monkeypatch.setattr(settings, "client_ip_header", "")
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    monkeypatch.setattr(settings, "login_ip_max_fails", 3)
    codes = []
    for i in range(5):
        r = raw_client.post("/api/auth/login",
                            json={"email": f"nobody{i}@x.com", "password": "wrongwrong"},
                            headers={"X-Forwarded-For": f"10.9.9.{i}, 203.0.113.50"})
        codes.append(r.status_code)
    assert codes[-1] == 429, codes


# --- 6. MCP OAuth grants: tenant-bound, lifecycle-checked ---------------------------------

def _pat(db_factory, user_id: int, tenant_id: int) -> str:
    from app.oauth_provider import _now
    token = "pat_test_" + str(user_id) + "_" + str(tenant_id)
    db = db_factory()
    db.add(OAuthToken(token_hash=hash_token(token), kind="access", client_id="c1",
                      user_id=user_id, tenant_id=tenant_id, scopes="palivane:read",
                      expires_at=_now() + timedelta(hours=1)))
    db.commit()
    db.close()
    return token


def test_mcp_oauth_token_must_match_the_users_tenant(client, db_factory):
    from app.mcp_remote import _oauth_user_id
    db = db_factory()
    other = users_cli.create_tenant(db, "other", "Other")
    other_id = other.id
    db.close()
    u = _admin(db_factory)
    good = _pat(db_factory, u.id, u.tenant_id)
    crossed = _pat(db_factory, u.id, other_id)
    db = db_factory()
    assert _oauth_user_id(good, db) == u.id
    assert _oauth_user_id(crossed, db) is None
    db.close()


def test_mcp_oauth_refuses_a_suspended_tenant(client, raw_client, db_factory):
    u = _admin(db_factory)
    token = _pat(db_factory, u.id, u.tenant_id)
    _set(db_factory, Tenant, u.tenant_id, status="suspended")
    r = raw_client.post("/api/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                           "params": {}},
                        headers={"content-type": "application/json",
                                 "accept": "application/json, text/event-stream",
                                 **_bearer(token)})
    assert r.status_code == 401


def test_mcp_oauth_tool_session_is_tenant_bound(client, db_factory, monkeypatch):
    """The tool's DB session gets bind_tenant (RLS) and the lifecycle check."""
    from app import mcp_remote
    u = _admin(db_factory)
    seen = {}
    monkeypatch.setattr("app.database.bind_tenant", lambda db, t: seen.setdefault("tenant", t))
    tok = mcp_remote._OAUTH_USER.set(u.id)
    try:
        user, db, gen = mcp_remote._caller_and_db()
        mcp_remote._close(db, gen)
    finally:
        mcp_remote._OAUTH_USER.reset(tok)
    assert user.id == u.id and seen["tenant"] == u.tenant_id


# --- 7. operator surface ------------------------------------------------------------------

def test_admin_routes_refuse_the_query_string_token(raw_client, monkeypatch):
    from app import main
    monkeypatch.setattr(main.settings, "metrics_token", "m3trics")
    monkeypatch.setattr(main.settings, "admin_token", "")
    assert raw_client.get("/api/admin/plans?token=m3trics").status_code == 401
    assert raw_client.get("/api/admin/plans", headers=_bearer("m3trics")).status_code == 200
    # /metrics scrapers keep ?token=.
    assert raw_client.get("/metrics?token=m3trics").status_code == 200


def test_separate_admin_token_replaces_the_metrics_token(raw_client, monkeypatch):
    from app import main
    monkeypatch.setattr(main.settings, "metrics_token", "m3trics")
    monkeypatch.setattr(main.settings, "admin_token", "adm1n")
    assert raw_client.get("/api/admin/plans", headers=_bearer("m3trics")).status_code == 401
    assert raw_client.get("/api/admin/plans", headers=_bearer("adm1n")).status_code == 200


def test_non_ascii_operator_token_is_a_401_not_a_500(raw_client, monkeypatch):
    from app import main
    monkeypatch.setattr(main.settings, "metrics_token", "m3trics")
    monkeypatch.setattr(main.settings, "admin_token", "")
    r = raw_client.get("/api/admin/plans",
                       headers={"Authorization": "Bearer t\xe9st".encode("latin-1")})
    assert r.status_code == 401
    assert raw_client.get("/metrics?token=%C3%A9").status_code == 401


# --- 9. warehouse hosts go through the SSRF guard -----------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "localhost"])
def test_snowflake_host_cannot_reach_internal_addresses(host):
    from app import warehouse_ai as wa
    with pytest.raises(httpx.ConnectError, match="blocked"):
        wa.snowflake_query(host, "jwt", "select 1", timeout=2)


def test_databricks_host_cannot_reach_internal_addresses():
    from app import warehouse_ai as wa
    with pytest.raises(httpx.ConnectError, match="blocked"):
        wa.databricks_token("169.254.169.254", "id", "secret", timeout=2)
    with pytest.raises(httpx.ConnectError, match="blocked"):
        wa.databricks_query("127.0.0.1", "tok", "wh", "select 1", timeout=2)


def test_warehouse_fetch_does_not_follow_redirects(monkeypatch):
    """A 3xx must not carry the Authorization header to wherever it points."""
    from app import netguard
    from app import warehouse_ai as wa

    def handler(request):
        if request.url.host == "evil.example":
            raise AssertionError("redirect was followed")
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    real = netguard.safe_client
    monkeypatch.setattr(netguard, "safe_client",
                        lambda **kw: httpx.Client(transport=httpx.MockTransport(handler), **kw))
    assert real().follow_redirects is False
    with pytest.raises((httpx.HTTPStatusError, ValueError)):
        wa.snowflake_query("acct.snowflakecomputing.com", "jwt", "select 1")


# --- 10. netguard allowlists globally-routable addresses ----------------------------------

@pytest.mark.parametrize("ip", [
    "100.64.0.1",                 # CGNAT / shared address space
    "100.127.255.254",
    "198.18.0.1",                 # benchmarking
    "::ffff:169.254.169.254",     # IPv4-mapped metadata
    "::ffff:127.0.0.1",
    "64:ff9b::a9fe:a9fe",         # NAT64 of 169.254.169.254
    "64:ff9b::7f00:1",            # NAT64 of 127.0.0.1
    "2002:a9fe:a9fe::1",          # 6to4 of 169.254.169.254
    "fd00::1",                    # ULA
])
def test_netguard_blocks_non_global_and_wrapped_addresses(ip):
    from app.netguard import _blocked_ip
    assert _blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8",
                                "64:ff9b::808:808"])
def test_netguard_allows_public_addresses(ip):
    from app.netguard import _blocked_ip
    assert _blocked_ip(ip) is False


# --- 11. a stale unverified domain claim can be superseded --------------------------------

def _other_admin_client(db_factory) -> TestClient:
    db = db_factory()
    users_cli.create_tenant(db, "squat", "Squatter")
    users_cli.create_user(db, "squat", "admin@squat.io", "password123", "admin")
    db.close()
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": "admin@squat.io", "password": "password123"})
    c.headers.update(_bearer(r.json()["access_token"]))
    return c


def test_stale_unverified_claim_is_superseded(client, db_factory):
    squatter = _other_admin_client(db_factory)
    d = squatter.post("/api/domains", json={"domain": "acme.com"}).json()
    assert client.post("/api/domains", json={"domain": "acme.com"}).status_code == 409   # fresh

    from app.domains import UNVERIFIED_CLAIM_TTL
    from app.oauth_provider import _now
    _set(db_factory, TenantDomain, d["id"], created_at=_now() - UNVERIFIED_CLAIM_TTL - timedelta(hours=1))
    r = client.post("/api/domains", json={"domain": "acme.com"})
    assert r.status_code == 200, r.text
    assert r.json()["token"] != d["token"]               # the squatter's TXT value is dead
    assert squatter.get("/api/domains").json()["domains"] == []


def test_verified_claim_is_never_superseded(client, db_factory):
    squatter = _other_admin_client(db_factory)
    d = squatter.post("/api/domains", json={"domain": "acme.com"}).json()
    from app.oauth_provider import _now
    _set(db_factory, TenantDomain, d["id"], verified=True, created_at=_now() - timedelta(days=365))
    assert client.post("/api/domains", json={"domain": "acme.com"}).status_code == 409


def test_logout_all_ends_oauth_grants_too(client, db_factory):
    """OAuth tokens carry no `tv`, so logout-everywhere revokes them explicitly."""
    from app.mcp_remote import _oauth_user_id
    u = _admin(db_factory)
    token = _pat(db_factory, u.id, u.tenant_id)
    assert client.post("/api/auth/logout-all").status_code == 200
    db = db_factory()
    assert _oauth_user_id(token, db) is None
    db.close()
