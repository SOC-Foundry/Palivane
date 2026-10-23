"""saas_connectors.sync_claimed_at: a scan's lock, apart from when it last finished

Revision ID: a7c4b7b8a6f7
Revises: f758200a1b4b
Create Date: 2026-10-22

The scheduler used to claim a connector by writing last_sync_at, and sync_connector wrote it
again at entry and committed the row (with the scan cursor) at the end. A scan can run longer
than the shortest interval, so a second instance could claim the same connector mid-scan and
the slower commit put an older time and an older cursor back. The claim now lives in its own
column and last_sync_at is written when a scan finishes (saas_connectors.sync_connector, #298).
"""
from alembic import op
import sqlalchemy as sa

revision = "a7c4b7b8a6f7"
down_revision = "f758200a1b4b"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("saas_connectors", schema=None) as batch_op:
        batch_op.add_column(sa.Column("sync_claimed_at", sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table("saas_connectors", schema=None) as batch_op:
        batch_op.drop_column("sync_claimed_at")
