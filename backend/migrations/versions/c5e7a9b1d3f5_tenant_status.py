"""tenant lifecycle status (active | suspended)

Revision ID: c5e7a9b1d3f5
Revises: b4d6f8a0c2e4
Create Date: 2026-07-13

"""
from alembic import op
import sqlalchemy as sa

revision = "c5e7a9b1d3f5"
down_revision = "b4d6f8a0c2e4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("status", sa.String(length=16), nullable=False,
                                       server_default="active"))


def downgrade():
    op.drop_column("tenants", "status")
