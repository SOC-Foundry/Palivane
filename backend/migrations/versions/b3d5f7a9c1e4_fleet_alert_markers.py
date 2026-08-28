"""fleet alert markers — edge-trigger state for gone-dark / dead-key webhook alerts

Revision ID: b3d5f7a9c1e4
Revises: a2c4e6b8d0f2
Create Date: 2026-08-28

"""
from alembic import op
import sqlalchemy as sa

revision = "b3d5f7a9c1e4"
down_revision = "a2c4e6b8d0f2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("sensor_heartbeats", sa.Column("dark_alerted_at", sa.DateTime(), nullable=True))
    op.add_column("api_keys", sa.Column("dead_alerted_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("api_keys", "dead_alerted_at")
    op.drop_column("sensor_heartbeats", "dark_alerted_at")
