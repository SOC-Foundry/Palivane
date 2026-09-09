"""Sensor drift visibility: parse-miss counters and the host-agent build on the heartbeat.

The gap these close: hooks fail open by design, so a vendor shape change leaves the sensor
checking in normally while extracting nothing. last_seen stays green and coverage is gone.
"""

from __future__ import annotations

from app.main import _parse_agent_ua


def _sensor(client, actor, plane):
    for row in client.get("/api/fleet").json()["sensors"]:
        if row["actor"] == actor and row["plane"] == plane:
            return row
    return None


def _key(client):
    return client.post("/api/apikeys", json={"label": "hook"}).json()["token"]


_UA = "palivane-hook/1.1.0 (claude-code/2.1.4)"


# --- User-Agent parsing ------------------------------------------------------------------

def test_agent_ua_parses_the_parenthetical():
    assert _parse_agent_ua("palivane-hook/1.1.0 (claude-code/2.1.4)") == ("claude-code", "2.1.4")


def test_agent_ua_without_a_version():
    assert _parse_agent_ua("palivane-hook/1.1.0 (claude-code)") == ("", "")


def test_agent_ua_of_an_older_client_is_empty():
    """Clients that predate this send no parenthetical, and must not blank what we know."""
    assert _parse_agent_ua("palivane-hook/1.0.0") == ("", "")
    assert _parse_agent_ua("") == ("", "")


# --- the ingest path ---------------------------------------------------------------------

def test_parse_miss_records_without_scoring(client, raw_client):
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "[palivane parse-miss]", "tool": "claude-code", "destination": "claude-code",
                              "parse_miss": True, "user": "drift@demo.local"},
                        headers={"X-Palivane-Token": _key(client), "User-Agent": _UA})
    assert r.status_code == 200
    body = r.json()
    assert body["parse_miss"] is True
    # A fail-open client must be able to read this like any other verdict.
    assert body["action"] == "allow" and body["severity"] == "none"

    hb = _sensor(client, "drift@demo.local", "ai-usage")
    assert hb is not None
    assert hb["parse_miss_count"] == 1
    assert hb["last_parse_miss"] is not None
    assert (hb["agent"], hb["agent_version"]) == ("claude-code", "2.1.4")


def test_parse_miss_creates_no_finding(client, raw_client):
    """There is no content to score, so a drift report must not manufacture a finding —
    otherwise a broken extractor would page the security team about itself, repeatedly."""
    before = client.get("/api/findings").json()["findings"]
    raw_client.post("/api/ingest/ai-usage",
                    json={"content": "[palivane parse-miss]", "tool": "claude-code", "destination": "claude-code",
                          "parse_miss": True, "user": "quiet@demo.local"},
                    headers={"X-Palivane-Token": _key(client), "User-Agent": _UA})
    assert len(client.get("/api/findings").json()["findings"]) == len(before)


def test_ordinary_traffic_leaves_the_counter_alone(client, raw_client):
    raw_client.post("/api/ingest/ai-usage",
                    json={"content": "just some ordinary text about the weather",
                          "tool": "claude-code", "destination": "claude-code",
                          "user": "fine@demo.local"},
                    headers={"X-Palivane-Token": _key(client), "User-Agent": _UA})
    hb = _sensor(client, "fine@demo.local", "ai-usage")
    assert hb is not None and hb["parse_miss_count"] == 0
    assert hb["agent"] == "claude-code"


def test_mcp_parse_miss_records_on_its_own_plane(client, raw_client):
    r = raw_client.post("/api/ingest/mcp",
                        json={"method": "tools/call", "tool": "claude-code",
                              "transport": "stdio", "parse_miss": True,
                              "user": "drift2@demo.local"},
                        headers={"X-Palivane-Token": _key(client), "User-Agent": _UA})
    assert r.status_code == 200 and r.json()["parse_miss"] is True
    hb = _sensor(client, "drift2@demo.local", "mcp")
    assert hb is not None and hb["parse_miss_count"] == 1
