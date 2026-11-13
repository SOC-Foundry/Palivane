"""On the mcp plane a sensor row is one per (actor, client) and the tools it called are
counted inside it. Keyed by tool, one coding agent was twenty or thirty rows (Bash, Read,
Edit, every MCP tool) and an insert per new name; at a few hundred people the Fleet ledger
drowned and the database took a write per distinct name."""
from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.main import _count_tool
from app.models import SensorHeartbeat

_UA = "palivane-hook/1.1.0 (claude-code/2.1.4)"


def _key(client, actor="dev@acme.com"):
    return client.post("/api/apikeys", json={"label": "hook", "actor": actor}).json()["token"]


def _mcp(raw_client, key, tool, user="dev@acme.com"):
    r = raw_client.post("/api/ingest/mcp",
                        json={"method": "tools/call", "tool": tool, "transport": "stdio",
                              "parse_miss": True, "user": user},
                        headers={"X-Palivane-Token": key, "User-Agent": _UA})
    assert r.status_code == 200, r.text


def _rows(client, actor, plane):
    return [r for r in client.get("/api/fleet").json()["sensors"]
            if r["actor"] == actor and r["plane"] == plane]


def test_mcp_tool_calls_count_inside_one_row(client, raw_client):
    key = _key(client)
    for tool in ("Bash", "Read", "Bash", "mcp__slack__search", "Edit"):
        _mcp(raw_client, key, tool)
    rows = _rows(client, "dev@acme.com", "mcp")
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "" and row["count"] == 5
    assert row["tools"] == {"Bash": 2, "Read": 1, "mcp__slack__search": 1, "Edit": 1}
    assert row["parse_miss_count"] == 5
    # The people ledger sees one sensor for the plane, not five.
    people = client.get("/api/fleet/people?attention=0").json()["people"]
    me = next(p for p in people if p["actor"] == "dev@acme.com")
    assert me["planes"] == {"mcp": 1} and me["sensors"] == 1


def test_two_clients_on_the_mcp_plane_stay_apart(client, raw_client):
    key = _key(client)
    _mcp(raw_client, key, "Bash")
    r = raw_client.post("/api/ingest/mcp",
                        json={"method": "tools/call", "tool": "Bash", "transport": "stdio",
                              "parse_miss": True, "user": "dev@acme.com"},
                        headers={"X-Palivane-Token": key, "User-Agent": "palivane-mcp/1.2.0"})
    assert r.status_code == 200
    rows = _rows(client, "dev@acme.com", "mcp")
    assert sorted(r["client"] for r in rows) == ["palivane-hook", "palivane-mcp"]
    assert all(r["tools"] == {"Bash": 1} for r in rows)


def test_other_planes_still_key_by_tool(client, raw_client):
    key = _key(client)
    for tool in ("claude-code", "cursor"):
        r = raw_client.post("/api/ingest/ai-usage",
                            json={"content": "please summarise the quarterly figures",
                                  "tool": tool, "user": "dev@acme.com"},
                            headers={"X-Palivane-Token": key, "User-Agent": _UA})
        assert r.status_code == 200, r.text
    rows = _rows(client, "dev@acme.com", "ai-usage")
    assert sorted(r["tool"] for r in rows) == ["claude-code", "cursor"]
    assert all(r["tools"] == {} for r in rows)


def test_the_tool_list_is_capped_by_evicting_the_least_called():
    tools = {}
    for i in range(200):
        tools = _count_tool(tools, f"t{i}")
    tools = _count_tool(tools, "t0")            # t0 is now the most-called
    assert len(tools) == 200
    tools = _count_tool(tools, "newcomer")      # over the cap: the least-called goes, not the newcomer
    assert len(tools) == 200 and "newcomer" in tools and "t0" in tools
    assert "t1" not in tools                    # count 1, alphabetically first among the ties


def test_the_migration_collapses_existing_rows(db_factory):
    from sqlalchemy import select
    spec = importlib.util.spec_from_file_location(
        "hb_mig", Path(__file__).resolve().parents[1] / "migrations" / "versions"
        / "98609b80f1be_heartbeat_tools_inside.py")
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    db = db_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = [
        # one developer's Claude Code hook, three tools
        SensorHeartbeat(tenant_id=1, actor="dev@acme.com", plane="mcp", tool="Bash", client="palivane-hook",
                        first_seen=now - timedelta(days=3), last_seen=now - timedelta(hours=2), count=10,
                        scan_fail_count=2, first_scan_fail=now - timedelta(days=1), last_scan_fail=now - timedelta(hours=5),
                        scan_fail_reasons={"timeout": 2}),
        SensorHeartbeat(tenant_id=1, actor="dev@acme.com", plane="mcp", tool="Read", client="palivane-hook",
                        first_seen=now - timedelta(days=2), last_seen=now - timedelta(hours=1), count=5,
                        parse_miss_count=1, last_parse_miss=now - timedelta(hours=1)),
        SensorHeartbeat(tenant_id=1, actor="dev@acme.com", plane="mcp", tool="Edit", client="palivane-hook",
                        first_seen=now - timedelta(days=1), last_seen=now - timedelta(hours=3), count=1,
                        scan_fail_count=1, first_scan_fail=now - timedelta(hours=4), last_scan_fail=now - timedelta(hours=4),
                        scan_fail_reasons={"network": 1}),
        # the same person through another client: its own row
        SensorHeartbeat(tenant_id=1, actor="dev@acme.com", plane="mcp", tool="Bash", client="palivane-mcp",
                        first_seen=now, last_seen=now, count=2),
        # another plane: untouched
        SensorHeartbeat(tenant_id=1, actor="dev@acme.com", plane="ai-usage", tool="claude-code",
                        client="palivane-hook", first_seen=now, last_seen=now, count=7),
        # another tenant: collapsed on its own
        SensorHeartbeat(tenant_id=2, actor="dev@acme.com", plane="mcp", tool="Bash", client="palivane-hook",
                        first_seen=now, last_seen=now, count=1),
    ]
    db.add_all(rows)
    db.commit()
    with db.bind.begin() as conn:
        assert mig.collapse_tools_inside(conn) == 2
    db.expire_all()
    mcp = (db.execute(select(SensorHeartbeat).where(SensorHeartbeat.plane == "mcp", SensorHeartbeat.tenant_id == 1))
             .scalars().all())
    by_client = {r.client: r for r in mcp}
    assert set(by_client) == {"palivane-hook", "palivane-mcp"}
    hook = by_client["palivane-hook"]
    assert hook.tool == "" and hook.tools == {"Bash": 10, "Read": 5, "Edit": 1}
    assert hook.count == 16 and hook.parse_miss_count == 1
    assert hook.first_seen == now - timedelta(days=3) and hook.last_seen == now - timedelta(hours=1)
    assert hook.scan_fail_count == 3 and hook.scan_fail_reasons == {"timeout": 2, "network": 1}
    assert hook.first_scan_fail == now - timedelta(days=1) and hook.last_scan_fail == now - timedelta(hours=4)
    assert by_client["palivane-mcp"].tools == {"Bash": 2}
    other = db.execute(select(SensorHeartbeat).where(SensorHeartbeat.plane == "ai-usage")).scalars().one()
    assert other.tool == "claude-code" and not other.tools
    assert db.execute(select(SensorHeartbeat).where(SensorHeartbeat.tenant_id == 2)).scalars().one().tools == {"Bash": 1}
    db.close()
