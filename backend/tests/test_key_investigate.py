"""A console_write API key can ask the AI analyst to investigate a finding.

The MCP server's investigate_finding tool calls POST /api/findings/{id}/investigate with a
console key. The route was missing from the key write allowlist, so it always answered 403
"an API key cannot call this endpoint", whatever the org's settings.
"""

from __future__ import annotations


def _key(client, scope):
    r = client.post("/api/apikeys", json={"label": "mcp", "scope": scope})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_write_key_reaches_the_investigate_route(client, raw_client):
    r = raw_client.post("/api/findings/1/investigate", headers=_key(client, "console_write"))
    # Past the key gate: the route's own answer (the analyst is off by default), not the
    # allowlist's refusal.
    assert r.status_code == 403
    assert "AI analyst is off" in r.json()["detail"]
    assert "API key cannot call" not in r.json()["detail"]


def test_read_key_still_cannot_post(client, raw_client):
    r = raw_client.post("/api/findings/1/investigate", headers=_key(client, "console_read"))
    assert r.status_code == 403 and "read-only" in r.json()["detail"]


def test_allowlist_is_still_exact(client, raw_client):
    # Only the investigate route was added; neighbours stay session-only.
    h = _key(client, "console_write")
    for path in ("/api/findings/1/investigate/extra", "/api/findings/x/investigate"):
        r = raw_client.post(path, headers=h)
        assert r.status_code in (403, 404, 405)
        if r.status_code == 403:
            assert "API key cannot call" in r.json()["detail"]
