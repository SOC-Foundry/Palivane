"""tenant.disabled_checks — per-tenant detection-policy toggles

Revision ID: d2e4f6a8b0c3
Revises: c1d3e5f7a9b2
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "d2e4f6a8b0c3"
down_revision = "c1d3e5f7a9b2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("disabled_checks", sa.String(length=2048), server_default=""))


def downgrade():
    op.drop_column("tenants", "disabled_checks")
