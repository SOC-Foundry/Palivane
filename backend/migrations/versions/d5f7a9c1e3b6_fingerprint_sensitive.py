"""content_fingerprints.sensitive — was the source doc's own scan a data-loss finding

Revision ID: d5f7a9c1e3b6
Revises: c4e6a8b0d2f4
Create Date: 2026-08-29

"""
from alembic import op
import sqlalchemy as sa

revision = "d5f7a9c1e3b6"
down_revision = "c4e6a8b0d2f4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("content_fingerprints",
                  sa.Column("sensitive", sa.Boolean(), server_default=sa.false()))


def downgrade():
    op.drop_column("content_fingerprints", "sensitive")
