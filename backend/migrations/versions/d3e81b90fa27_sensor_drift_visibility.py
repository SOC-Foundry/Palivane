"""sensor_heartbeats: host agent build + parse-miss counters

Fail-open is the right default for a capture client — Palivane being down must never break
a developer's session — but it has a cost this table was already built to cover: a sensor
that stops reporting looks exactly like a quiet one. SensorHeartbeat solved that for TOTAL
failure.

It does not cover PARTIAL failure, which is the likelier one. When a vendor renames a field
the hook keeps firing, keeps posting, and the heartbeat stays green while the extractor
returns nothing. That is worse than going dark, because dark pages someone.

So two additions. `parse_miss_count`/`last_parse_miss` record the case where a client
recognised an event and got nothing out of it, which is the signal that shape drift has
started. `agent`/`agent_version` record the HOST build the sensor ran inside, parsed from
the parenthetical of our own User-Agent, so the answer to "when did this start" is a version
rather than a date.

All four are additive with defaults: existing rows and every client that predates the new
User-Agent keep working untouched, and simply report nothing for these columns.

Revision ID: d3e81b90fa27
Revises: c1f4a9e77b02
"""

import sqlalchemy as sa
from alembic import op

revision = "d3e81b90fa27"
down_revision = "c1f4a9e77b02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sensor_heartbeats", sa.Column("agent", sa.String(48), server_default=""))
    op.add_column("sensor_heartbeats", sa.Column("agent_version", sa.String(24), server_default=""))
    op.add_column("sensor_heartbeats",
                  sa.Column("parse_miss_count", sa.Integer(), server_default="0"))
    op.add_column("sensor_heartbeats", sa.Column("last_parse_miss", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("sensor_heartbeats", "last_parse_miss")
    op.drop_column("sensor_heartbeats", "parse_miss_count")
    op.drop_column("sensor_heartbeats", "agent_version")
    op.drop_column("sensor_heartbeats", "agent")
