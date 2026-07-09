"""agent_roles: least-privilege roles for agents (Phase 1)

Revision ID: b6d8f0a2c4e7
Revises: a5c7e9b1d3f6
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "b6d8f0a2c4e7"
down_revision = "a5c7e9b1d3f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("allow_tools", sa.String(length=2048), server_default=""),
        sa.Column("allow_servers", sa.String(length=2048), server_default=""),
        sa.Column("deny", sa.String(length=2048), server_default=""),
        sa.Column("default_allow", sa.Boolean(), server_default=sa.false()),
        sa.Column("enforce", sa.Boolean(), server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_agentrole_tenant_name"),
    )
    op.create_index("ix_agent_roles_tenant_id", "agent_roles", ["tenant_id"])


def downgrade():
    op.drop_index("ix_agent_roles_tenant_id", table_name="agent_roles")
    op.drop_table("agent_roles")
