"""policy_overrides: per-user / per-group detection-policy overrides

Revision ID: e3f5a7b9c1d4
Revises: d2e4f6a8b0c3
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "e3f5a7b9c1d4"
down_revision = "d2e4f6a8b0c3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "policy_overrides",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("scope", sa.String(length=8), server_default="user"),
        sa.Column("match", sa.String(length=320), server_default=""),
        sa.Column("label", sa.String(length=128), server_default=""),
        sa.Column("disabled_checks", sa.String(length=2048), server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "scope", "match", name="uq_override_scope_match"),
    )
    op.create_index("ix_policy_overrides_tenant_id", "policy_overrides", ["tenant_id"])


def downgrade():
    op.drop_index("ix_policy_overrides_tenant_id", table_name="policy_overrides")
    op.drop_table("policy_overrides")
