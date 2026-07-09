"""tenant.oversharing_rules — need-to-know access-governance rules

Revision ID: f4a6b8c0d2e5
Revises: e3f5a7b9c1d4
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "f4a6b8c0d2e5"
down_revision = "e3f5a7b9c1d4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("oversharing_rules", sa.String(length=4096), server_default=""))


def downgrade():
    op.drop_column("tenants", "oversharing_rules")
