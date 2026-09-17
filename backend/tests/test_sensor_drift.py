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


# --- open vs. needs-review ---------------------------------------------------------------
# Status and severity are independent axes: "open" means nobody has reviewed the row, which
# is true of a benign finding too. These pin that /api/stats reports both numbers, so a
# queue of benign records cannot inflate the one people act on.

def test_stats_separates_unreviewed_from_actionable(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "stats"}).json()["token"]
    for content in ("AKIA4YTGH2NBQF7XZP3K is the key", "SSN 123-45-6789"):
        raw_client.post("/api/ingest/ai-usage",
                        json={"content": content, "destination": "https://chatgpt.com/",
                              "user": "a@demo.local"},
                        headers={"X-Palivane-Token": key})
    stats = client.get("/api/stats").json()
    assert "open_needs_review" in stats
    # Nothing benign was persisted here, so the two numbers agree — the sub-line stays hidden.
    assert stats["open_needs_review"] == stats["open"]


def test_benign_counts_as_open_but_not_as_work(client, db_factory):
    """A benign row is unreviewed (open) and needs nothing doing. Both at once.

    Inserted directly: reaching a genuinely benign verdict through ai-usage is awkward
    because sending anything to an unsanctioned destination already scores low, and the
    behaviour under test is the counting rule, not the scorer."""
    from app.models import Finding, Tenant

    db = db_factory()
    tenant_id = db.query(Tenant).filter(Tenant.slug == "acme").one().id
    db.add(Finding(tenant_id=tenant_id, severity="benign", status="open",
                   surface="ai_usage", channel="llm", sender="quiet@demo.local"))
    db.commit()
    db.close()

    stats = client.get("/api/stats").json()
    assert stats["open"] >= 1
    assert stats["open"] > stats["open_needs_review"], (
        "a benign open row must count as unreviewed but not as work")


# --- /api/capture/hooked: liveness, not installation ---------------------------------------

def _hb(db_factory, tenant_id, actor, tool, client, minutes_ago=0):
    from datetime import datetime, timedelta, timezone
    from app.models import SensorHeartbeat
    db = db_factory()
    t = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
    db.add(SensorHeartbeat(tenant_id=tenant_id, actor=actor, tool=tool, client=client,
                           plane="ai-usage", first_seen=t, last_seen=t, count=1))
    db.commit(); db.close()


def test_hooked_reports_a_live_hook(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "k", "actor": "dev@acme.com"}).json()["token"]
    me = client.get("/api/auth/me").json()["user"]
    _hb(db_factory, me["tenant_id"], "dev@acme.com", "claude-code", "palivane-hook", 1)
    r = raw_client.get("/api/capture/hooked", headers={"X-Palivane-Token": key})
    assert r.status_code == 200, r.text
    assert "claude-code" in r.json()["tools"]


def test_a_stale_hook_is_not_deferred_to(client, raw_client, db_factory):
    """The whole point of liveness over installation: a hook that stopped reporting must NOT
    keep the proxy quiet. "A hook is installed" is a signal the monitored person can remove;
    "a hook reported two minutes ago" is not."""
    key = client.post("/api/apikeys", json={"label": "k2", "actor": "stale@acme.com"}).json()["token"]
    me = client.get("/api/auth/me").json()["user"]
    _hb(db_factory, me["tenant_id"], "stale@acme.com", "claude-code", "palivane-hook", 600)
    r = raw_client.get("/api/capture/hooked", headers={"X-Palivane-Token": key})
    assert r.json()["tools"] == []


def test_the_proxys_own_heartbeat_is_not_mistaken_for_a_hook(client, raw_client, db_factory):
    """Deferring to itself would disable capture entirely, quietly."""
    key = client.post("/api/apikeys", json={"label": "k3", "actor": "self@acme.com"}).json()["token"]
    me = client.get("/api/auth/me").json()["user"]
    _hb(db_factory, me["tenant_id"], "self@acme.com", "claude-code", "palivane-proxy", 1)
    r = raw_client.get("/api/capture/hooked", headers={"X-Palivane-Token": key})
    assert r.json()["tools"] == []


def test_another_persons_hook_does_not_silence_yours(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "k4", "actor": "mine@acme.com"}).json()["token"]
    me = client.get("/api/auth/me").json()["user"]
    _hb(db_factory, me["tenant_id"], "someone-else@acme.com", "claude-code", "palivane-hook", 1)
    r = raw_client.get("/api/capture/hooked", headers={"X-Palivane-Token": key})
    assert r.json()["tools"] == []
