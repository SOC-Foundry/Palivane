"""findings.owner_response — the attributed answer from the person a finding belongs to

Revision ID: 54b3d4b8a602
Revises: d5f7a9c1e3b6
Create Date: 2026-09-02

"""
from alembic import op
import sqlalchemy as sa

revision = "54b3d4b8a602"
down_revision = "d5f7a9c1e3b6"
branch_labels = None
depends_on = None


def upgrade():
    # JSON rather than columns: {action, note, by, at}. One shape, read whole, never
    # filtered on — the queue an admin works is still status + severity.
    op.add_column("findings", sa.Column("owner_response", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("findings", "owner_response")
