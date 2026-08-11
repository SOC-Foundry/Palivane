"""saas_connectors — stored credentials for live OAuth-grant pulls from SaaS admin APIs

Revision ID: a1c3e5b7d9f2
Revises: e6a8c0d2f4b7
Create Date: 2026-08-11
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1c3e5b7d9f2"
down_revision: Union[str, None] = "e6a8c0d2f4b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saas_connectors",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"),
                  index=True, nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("label", sa.String(128), server_default=""),
        sa.Column("credentials_enc", sa.Text(), server_default=""),
        sa.Column("active", sa.Boolean(), server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(), nullable=True),
        sa.Column("last_sync_status", sa.String(16), server_default=""),
        sa.Column("last_sync_detail", sa.String(512), server_default=""),
        sa.UniqueConstraint("tenant_id", "platform", "label",
                            name="uq_connector_tenant_platform_label"),
    )


def downgrade() -> None:
    op.drop_table("saas_connectors")
