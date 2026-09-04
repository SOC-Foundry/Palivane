"""tenant.scim_token_hash — per-org SCIM 2.0 provisioning token

Revision ID: 68812733d409
Revises: b3d5f7a9c1e2
Create Date: 2026-09-04

"""
from alembic import op
import sqlalchemy as sa

revision = "68812733d409"
down_revision = "b3d5f7a9c1e2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("scim_token_hash", sa.String(length=64),
                                       server_default=""))


def downgrade():
    op.drop_column("tenants", "scim_token_hash")
