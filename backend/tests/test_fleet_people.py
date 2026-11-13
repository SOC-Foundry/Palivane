"""Fleet rolled up per person: one row per actor, paged, worst first, with an attention
filter — and scans that failed open rolled up per device. A sensor row is keyed by tool, so
one developer is twenty or thirty rows; the flat list capped at 2000 and, sorted newest
first, lost the dark sensors first at a few hundred people."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _tenant_id(db_factory, slug="acme"):
    from app.models import Tenant
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == slug).one().id
    finally:
        db.close()


def _hb(db_factory, tenant_id, actor, tool, client="palivane-hook", client_version="",
        hours_ago=0.0, plane="ai-usage", count=1, fail=0, fail_reasons=None, fail_hours_ago=1.0):
    from app.models import SensorHeartbeat
    db = db_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    t = now - timedelta(hours=hours_ago)
    row = SensorHeartbeat(tenant_id=tenant_id, actor=actor, tool=tool, client=client,
                          client_version=client_version, plane=plane, first_seen=t, last_seen=t,
                          count=count)
    if fail:
        row.scan_fail_count = fail
        row.first_scan_fail = now - timedelta(hours=fail_hours_ago + 1)
        row.last_scan_fail = now - timedelta(hours=fail_hours_ago)
        row.scan_fail_reasons = fail_reasons or {"timeout": fail}
    db.add(row)
    db.commit()
    db.close()


def _latest(client):
    return client.get("/api/fleet?sensors=0").json()["latest_client_versions"]


def test_one_row_per_person_with_the_tools_inside(client, db_factory):
    tid = _tenant_id(db_factory)
    v = _latest(client)["palivane-hook"]
    for tool in ("Bash", "Read", "Edit", "Grep", "mcp__slack__search"):
        _hb(db_factory, tid, "dev@acme.com", tool, client_version=v, plane="mcp", count=10)
    _hb(db_factory, tid, "dev@acme.com", "claude-code", client_version=v, plane="ai-usage", count=3)
    d = client.get("/api/fleet/people?attention=0").json()
    assert d["total"] == 1 and len(d["people"]) == 1
    p = d["people"][0]
    assert p["actor"] == "dev@acme.com"
    assert p["sensors"] == 6 and p["planes"] == {"mcp": 5, "ai-usage": 1}
    assert p["events"] == 53 and p["worst"] == "fresh"
    assert len(p["rows"]) == 6 and {r["tool"] for r in p["rows"]} >= {"Bash", "claude-code"}
    assert d["summary"] == {"people": 1, "attention": 0, "fresh": 1, "stale": 0, "dark": 0}


def test_attention_is_the_default_and_dark_comes_first(client, db_factory):
    tid = _tenant_id(db_factory)
    v = _latest(client)["palivane-hook"]
    _hb(db_factory, tid, "fresh@acme.com", "Bash", client_version=v)
    _hb(db_factory, tid, "stale@acme.com", "Bash", client_version=v, hours_ago=30)
    _hb(db_factory, tid, "dark@acme.com", "Bash", client_version=v, hours_ago=100)
    # A person whose NEWEST sensor is fresh but whose oldest went dark is still dark:
    # sorting by newest-first is what hid these.
    _hb(db_factory, tid, "mixed@acme.com", "Bash", client_version=v)
    _hb(db_factory, tid, "mixed@acme.com", "Read", client_version=v, hours_ago=200)
    d = client.get("/api/fleet/people").json()
    assert d["attention"] is True
    assert [p["actor"] for p in d["people"]] == ["mixed@acme.com", "dark@acme.com", "stale@acme.com"]
    assert [p["worst"] for p in d["people"]] == ["dark", "dark", "stale"]
    assert d["summary"] == {"people": 4, "attention": 3, "fresh": 1, "stale": 1, "dark": 2}
    everyone = client.get("/api/fleet/people?attention=0").json()
    assert everyone["total"] == 4 and everyone["people"][-1]["actor"] == "fresh@acme.com"


def test_failed_open_and_a_stale_build_need_attention_even_when_fresh(client, db_factory):
    tid = _tenant_id(db_factory)
    v = _latest(client)["palivane-hook"]
    _hb(db_factory, tid, "failing@acme.com", "Bash", client_version=v, fail=4)
    _hb(db_factory, tid, "old-build@acme.com", "Bash", client_version="0.0.1")
    _hb(db_factory, tid, "retired@acme.com", "Bash", client="palivane-guard", client_version="0.4.0")
    _hb(db_factory, tid, "fine@acme.com", "Bash", client_version=v)
    d = client.get("/api/fleet/people").json()
    by = {p["actor"]: p for p in d["people"]}
    assert set(by) == {"failing@acme.com", "old-build@acme.com", "retired@acme.com"}
    assert by["failing@acme.com"]["failed_open"] == 4
    assert by["old-build@acme.com"]["stale_builds"] == 1 and by["old-build@acme.com"]["retired_builds"] == 0
    assert by["retired@acme.com"]["stale_builds"] == 1 and by["retired@acme.com"]["retired_builds"] == 1
    # A failure older than the 7-day window no longer needs attention.
    _hb(db_factory, tid, "healed@acme.com", "Bash", client_version=v, fail=2, fail_hours_ago=24 * 9)
    assert "healed@acme.com" not in {p["actor"] for p in client.get("/api/fleet/people").json()["people"]}


def test_paging_and_search_are_server_side(client, db_factory):
    tid = _tenant_id(db_factory)
    v = _latest(client)["palivane-hook"]
    for i in range(7):
        _hb(db_factory, tid, f"p{i}@acme.com", "Bash", client_version=v, hours_ago=100 + i)
    first = client.get("/api/fleet/people?limit=3").json()
    second = client.get("/api/fleet/people?limit=3&offset=3").json()
    assert first["total"] == second["total"] == 7
    assert [p["actor"] for p in first["people"]] == ["p6@acme.com", "p5@acme.com", "p4@acme.com"]
    assert [p["actor"] for p in second["people"]] == ["p3@acme.com", "p2@acme.com", "p1@acme.com"]
    found = client.get("/api/fleet/people?q=P3&attention=0").json()
    assert found["total"] == 1 and found["people"][0]["actor"] == "p3@acme.com"


def test_another_tenants_sensors_are_not_in_the_ledger(client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta")
    db.close()
    _hb(db_factory, _tenant_id(db_factory, "beta"), "them@beta.com", "Bash", hours_ago=100)
    _hb(db_factory, _tenant_id(db_factory), "us@acme.com", "Bash", hours_ago=100)
    d = client.get("/api/fleet/people").json()
    assert [p["actor"] for p in d["people"]] == ["us@acme.com"]
    assert d["summary"]["people"] == 1


def test_failed_open_rolls_up_per_device_on_the_fleet_summary(client, db_factory):
    tid = _tenant_id(db_factory)
    v = _latest(client)["palivane-hook"]
    # One laptop's Claude Code hook timed out across five tools: one device, five sensors.
    for tool in ("Bash", "Read", "Edit", "Grep", "Glob"):
        _hb(db_factory, tid, "dev@acme.com", tool, client_version=v, plane="mcp", fail=3,
            fail_reasons={"timeout": 2, "network": 1})
    _hb(db_factory, tid, "dev@acme.com", "cursor", client="palivane-cursor-hook",
        client_version="0.8.0", plane="ai-usage", fail=1, fail_reasons={"server-error": 1})
    _hb(db_factory, tid, "other@acme.com", "Bash", client_version=v, fail=40)
    d = client.get("/api/fleet?sensors=0").json()
    assert d["sensors"] == []                                   # left out on request
    assert d["summary"]["failed_open"] == 7 and d["summary"]["failed_open_devices"] == 3
    devs = d["failed_open_devices"]
    assert [(x["actor"], x["client"], x["sensors"], x["failed_open"]) for x in devs] == [
        ("other@acme.com", "palivane-hook", 1, 40),
        ("dev@acme.com", "palivane-hook", 5, 15),
        ("dev@acme.com", "palivane-cursor-hook", 1, 1),
    ]
    assert devs[1]["reasons"] == {"timeout": 10, "network": 5}
    assert sorted(devs[1]["tools"]) == ["mcp/Bash", "mcp/Edit", "mcp/Glob", "mcp/Grep", "mcp/Read"]
    assert devs[2]["client_current"] is False                  # the stale cursor build is flagged


def test_summary_counts_in_sql_match_the_rows(client, db_factory):
    tid = _tenant_id(db_factory)
    v = _latest(client)["palivane-hook"]
    _hb(db_factory, tid, "a@acme.com", "Bash", client_version=v)
    _hb(db_factory, tid, "a@acme.com", "Read", client_version=v, hours_ago=30)
    _hb(db_factory, tid, "b@acme.com", "Bash", client_version="0.0.1", hours_ago=100)
    _hb(db_factory, tid, "c@acme.com", "Bash", client="palivane-guard", client_version="0.4.0")
    d = client.get("/api/fleet").json()
    s = d["summary"]
    assert (s["actors"], s["sensors"], s["fresh"], s["stale"], s["dark"]) == (3, 4, 2, 1, 1)
    assert s["stale_clients"] == 2 and s["retired_clients"] == 1
    assert sum(1 for r in d["sensors"] if not r["client_current"]) == 2
