"""sensor_heartbeats.tools: the mcp plane counts its tools inside one row per actor+client

On the mcp plane `tool` is the tool CALLED, an open namespace, so keyed by tool one coding
agent was twenty or thirty sensor rows (Bash, Read, Edit, every MCP tool) and an insert per
new name. The row is now one per (actor, client) with a {tool: count} JSON inside it, capped
in main._record_heartbeat. Existing mcp rows are collapsed here: counts summed, first/last
seen and scan-failure fields merged, the row seen last kept. Every other plane is untouched.

Revision ID: 98609b80f1be
Revises: d0d67dc07078
"""
import json
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision = "98609b80f1be"
down_revision = "d0d67dc07078"
branch_labels = None
depends_on = None

_TOOLS_INSIDE_PLANES = ("mcp",)


def _dt(v):
    if v is None or isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None


def _earliest(a, b):
    return b if a is None else a if b is None else min(a, b)


def _latest(a, b):
    return b if a is None else a if b is None else max(a, b)


def _json(v):
    if isinstance(v, dict):
        return v
    try:
        return json.loads(v) if v else {}
    except (TypeError, ValueError):
        return {}


def collapse_tools_inside(conn) -> int:
    """Collapse per-tool rows on the tools-inside planes into one row per (tenant, actor,
    client). Returns the number of rows removed. Plain SQL so it runs on sqlite and
    Postgres alike, from alembic or a test."""
    t = sa.table(
        "sensor_heartbeats",
        sa.column("id", sa.Integer), sa.column("tenant_id", sa.Integer),
        sa.column("actor", sa.String), sa.column("plane", sa.String), sa.column("tool", sa.String),
        sa.column("client", sa.String), sa.column("first_seen", sa.DateTime),
        sa.column("last_seen", sa.DateTime), sa.column("count", sa.Integer),
        sa.column("tools", sa.JSON), sa.column("parse_miss_count", sa.Integer),
        sa.column("last_parse_miss", sa.DateTime), sa.column("scan_fail_count", sa.Integer),
        sa.column("first_scan_fail", sa.DateTime), sa.column("last_scan_fail", sa.DateTime),
        sa.column("scan_fail_reasons", sa.JSON),
    )
    rows = conn.execute(sa.select(t).where(t.c.plane.in_(_TOOLS_INSIDE_PLANES))).mappings().all()
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r["tenant_id"], r["actor"] or "", r["plane"], r["client"] or ""), []).append(dict(r))
    removed = 0
    for members in groups.values():
        members.sort(key=lambda r: (_dt(r["last_seen"]) or datetime.min, r["id"]))
        keep = members[-1]
        tools: dict = {}
        reasons: dict = {}
        count = parse_miss = fails = 0
        first_seen = last_seen = last_parse_miss = first_fail = last_fail = None
        for r in members:
            if r["tool"]:
                tools[r["tool"]] = tools.get(r["tool"], 0) + int(r["count"] or 0)
            for k, v in _json(r["tools"]).items():
                tools[k] = tools.get(k, 0) + int(v or 0)
            count += int(r["count"] or 0)
            parse_miss += int(r["parse_miss_count"] or 0)
            fails += int(r["scan_fail_count"] or 0)
            for k, v in _json(r["scan_fail_reasons"]).items():
                reasons[k] = reasons.get(k, 0) + int(v or 0)
            first_seen = _earliest(first_seen, _dt(r["first_seen"]))
            last_seen = _latest(last_seen, _dt(r["last_seen"]))
            last_parse_miss = _latest(last_parse_miss, _dt(r["last_parse_miss"]))
            first_fail = _earliest(first_fail, _dt(r["first_scan_fail"]))
            last_fail = _latest(last_fail, _dt(r["last_scan_fail"]))
        conn.execute(sa.update(t).where(t.c.id == keep["id"]).values(
            tool="", tools=tools, count=count, parse_miss_count=parse_miss,
            scan_fail_count=fails, scan_fail_reasons=reasons,
            first_seen=first_seen, last_seen=last_seen, last_parse_miss=last_parse_miss,
            first_scan_fail=first_fail, last_scan_fail=last_fail))
        gone = [r["id"] for r in members if r["id"] != keep["id"]]
        if gone:
            conn.execute(sa.delete(t).where(t.c.id.in_(gone)))
            removed += len(gone)
    return removed


def upgrade() -> None:
    op.add_column("sensor_heartbeats", sa.Column("tools", sa.JSON(), nullable=True))
    collapse_tools_inside(op.get_bind())


def downgrade() -> None:
    # The collapsed rows stay collapsed (their per-tool split is gone); only the column goes.
    op.drop_column("sensor_heartbeats", "tools")
