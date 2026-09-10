"""Remote MCP endpoint (/api/mcp): who may reach it, and as whom.

The transport multiplexes every tool call over one POST, so the REST write-route allowlist
cannot gate it. These pin the two properties that replace it: only a console-scoped key
gets in at all, and a tool whose REST twin is admin-gated still runs require_admin on the
user the key acts as — which a direct call to the endpoint function would otherwise skip.
"""

from __future__ import annotations

import pytest

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}}
HDRS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


def _key(client, scope):
    return client.post("/api/apikeys", json={"label": f"mcp-{scope}", "scope": scope}).json()["token"]


def test_unauthenticated_is_refused(raw_client):
    r = raw_client.post("/api/mcp/", json=INIT, headers=HDRS)
    assert r.status_code == 401
    assert "console-scoped" in r.text


def test_ingest_key_is_refused_exactly_like_a_fake_one(client, raw_client):
    """The 93beeb3 property, carried onto this transport: a wrong-scope key must not be
    distinguishable from an invented one, or the error confirms the key is real."""
    ingest = raw_client.post("/api/mcp/", json=INIT,
                             headers={**HDRS, "Authorization": f"Bearer {_key(client, 'ingest')}"})
    bogus = raw_client.post("/api/mcp/", json=INIT,
                            headers={**HDRS, "Authorization": "Bearer ak_deadbeefdeadbeefdead"})
    assert ingest.status_code == bogus.status_code == 401
    assert ingest.text == bogus.text


def test_console_keys_get_past_authentication(client):
    """Both console scopes reach the transport; neither is refused at the door.

    One lifespan entry for both cases on purpose: StreamableHTTPSessionManager.run() is
    single-use per instance, so a parametrized test that enters it twice fails on the
    second with "can only be called once". Production never hits that (one lifespan per
    process) but it constrains how this can be tested.
    """
    from fastapi.testclient import TestClient
    from app.main import app

    tokens = {scope: _key(client, scope) for scope in ("console_read", "console_write")}
    with TestClient(app) as live:
        for scope, token in tokens.items():
            r = live.post("/api/mcp/", json=INIT,
                          headers={**HDRS, "Authorization": f"Bearer {token}"})
            assert r.status_code != 401, f"{scope}: {r.text}"


def test_admin_gated_tool_follows_the_users_role(client, db_factory):
    """Calling an endpoint function directly skips its Depends(), so the tool must run
    require_admin itself. Demote the key's owner and the admin tool has to stop working
    while the plain read keeps going."""
    from app.mcp_remote import _read
    from app import main
    from app.models import ApiKey, User

    token = _key(client, "console_read")
    db = db_factory()
    key = db.query(ApiKey).filter(ApiKey.prefix == token[:11]).one()
    from app.mcp_remote import _CALLER
    reset = _CALLER.set(key.id)
    try:
        assert _read(main.list_findings, admin=False, limit=1) is not None
        assert _read(main.usage, admin=True) is not None      # owner is an admin

        owner = db.get(User, key.user_id)
        owner.role = "analyst"
        db.commit()

        from fastapi import HTTPException
        assert _read(main.list_findings, admin=False, limit=1) is not None   # still readable
        with pytest.raises(HTTPException) as e:
            _read(main.usage, admin=True)
        assert e.value.status_code == 403
    finally:
        _CALLER.reset(reset)
        db.close()


def test_only_read_tools_are_exposed(client):
    """No write tool exists yet — deliberately, because the allowlist that gates writes on
    the REST path has no equivalent here. If one is added, this test should be the thing
    that makes someone decide how it is authorized."""
    from app.mcp_remote import mcp
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert names == {"list_findings", "get_finding", "ai_tool_inventory",
                     "list_connectors", "gateway_usage"}
    assert not {n for n in names if "set_" in n or "sync" in n}


def test_bare_path_answers_the_challenge_instead_of_redirecting(raw_client):
    """`claude mcp add … https://app.palivane.io/api/mcp` stores the slashless URL, and MCP
    clients start OAuth discovery from the 401's WWW-Authenticate header. Starlette's Mount
    only matches `/api/mcp/…`, so the bare path used to fall through — to a 307 locally, and
    in production to the GET-only SPA catch-all, which answered a POST with a bare 405. Both
    spellings must serve the endpoint itself and carry the challenge.
    """
    for path in ("/api/mcp", "/api/mcp/"):
        r = raw_client.post(path, json=INIT, headers=HDRS)
        assert r.status_code == 401, f"{path}: {r.status_code}"
        wa = r.headers.get("www-authenticate", "")
        assert wa.startswith("Bearer "), path
        # RFC 9728: the challenge points at the protected-resource metadata so a client can
        # discover the auth server without probing well-known paths by convention.
        assert 'resource_metadata="' in wa and \
               "/.well-known/oauth-protected-resource/api/mcp" in wa, wa
