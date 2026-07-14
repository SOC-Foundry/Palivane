"""per-tenant resource quota overrides (users, api keys, daily ingest)

Revision ID: b4d6f8a0c2e4
Revises: a3c5e7b9d1f2
Create Date: 2026-07-13

"""
from alembic import op
import sqlalchemy as sa

revision = "b4d6f8a0c2e4"
down_revision = "a3c5e7b9d1f2"
branch_labels = None
depends_on = None


def upgrade():
    for col in ("quota_users", "quota_api_keys", "quota_ingest_per_day"):
        op.add_column("tenants", sa.Column(col, sa.Integer(), server_default="0"))


def downgrade():
    for col in ("quota_ingest_per_day", "quota_api_keys", "quota_users"):
        op.drop_column("tenants", col)
