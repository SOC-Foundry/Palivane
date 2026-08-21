"""tenant store_content (metadata-only default) + per-tenant wrapped DEK

Revision ID: f8b0d2c4e6a9
Revises: e7a9c1b3d5f8
Create Date: 2026-07-15

"""
from alembic import op
import sqlalchemy as sa

revision = "f8b0d2c4e6a9"
down_revision = "e7a9c1b3d5f8"
branch_labels = None
depends_on = None


def upgrade():
    # Nullable tri-state: NULL = inherit the global PALIVANE_STORE_CONTENT (off).
    op.add_column("tenants", sa.Column("store_content", sa.Boolean(), nullable=True))
    op.add_column("tenants", sa.Column("dek_wrapped", sa.Text(), server_default=""))


def downgrade():
    op.drop_column("tenants", "dek_wrapped")
    op.drop_column("tenants", "store_content")
