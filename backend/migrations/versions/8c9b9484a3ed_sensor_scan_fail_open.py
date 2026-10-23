"""sensor_heartbeats: scans that failed open (SEC-01)

Every capture client (the five agent hooks and the desktop egress proxy) fails open when a
scan cannot complete: a timeout, a network error, a 5xx, a rejected key, or its circuit
breaker standing down. That stays: Palivane being unreachable must never block the user.
But each such pass is a moment the sensor was not a sensor, and until now it was folded
silently into "allow". Clients now count those locally and report the tally (counts and
reasons, never content) on their next successful request; these columns hold the running
total per sensor so the Fleet view can say "N scans failed open since T, reason X".

Additive with defaults: existing rows and older clients that send no tally are untouched.

Revision ID: 8c9b9484a3ed
Revises: a7c4b7b8a6f7
"""

import sqlalchemy as sa
from alembic import op

revision = "8c9b9484a3ed"
down_revision = "a7c4b7b8a6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sensor_heartbeats",
                  sa.Column("scan_fail_count", sa.Integer(), server_default="0"))
    op.add_column("sensor_heartbeats", sa.Column("first_scan_fail", sa.DateTime(), nullable=True))
    op.add_column("sensor_heartbeats", sa.Column("last_scan_fail", sa.DateTime(), nullable=True))
    op.add_column("sensor_heartbeats", sa.Column("scan_fail_reasons", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("sensor_heartbeats", "scan_fail_reasons")
    op.drop_column("sensor_heartbeats", "last_scan_fail")
    op.drop_column("sensor_heartbeats", "first_scan_fail")
    op.drop_column("sensor_heartbeats", "scan_fail_count")
