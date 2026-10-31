"""Sensor heartbeats: one row per client

The fleet-health ledger was unique on (tenant, actor, plane, tool), so two clients reporting
the same tool for one person (the Claude Code hook and palivane-mcp both send "Bash") shared
a row and the second hid the first. The client is now part of the key.

Old rows keep their client; a NULL client is set to '' first (a NULL would never match and
never collide). The new key is looser than the old one, so no existing rows conflict.

Revision ID: f115f9a37e03
Revises: 540250ff34f0
"""

import sqlalchemy as sa
from alembic import op

revision = "f115f9a37e03"
down_revision = "540250ff34f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("UPDATE sensor_heartbeats SET client = '' WHERE client IS NULL"))
    with op.batch_alter_table("sensor_heartbeats") as b:
        b.drop_constraint("uq_heartbeat_scope", type_="unique")
        b.create_unique_constraint("uq_heartbeat_sensor",
                                   ["tenant_id", "actor", "plane", "tool", "client"])


def downgrade() -> None:
    # Collapsing back can collide (two clients, one tool); keep each scope's latest row.
    op.execute(sa.text(
        "DELETE FROM sensor_heartbeats WHERE id NOT IN ("
        " SELECT MAX(id) FROM sensor_heartbeats GROUP BY tenant_id, actor, plane, tool)"))
    with op.batch_alter_table("sensor_heartbeats") as b:
        b.drop_constraint("uq_heartbeat_sensor", type_="unique")
        b.create_unique_constraint("uq_heartbeat_scope", ["tenant_id", "actor", "plane", "tool"])
