"""agents table + findings.agent (agent identity, Phase 0)

Revision ID: a5c7e9b1d3f6
Revises: f4a6b8c0d2e5
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "a5c7e9b1d3f6"
down_revision = "f4a6b8c0d2e5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), server_default="service"),
        sa.Column("role", sa.String(length=64), server_default=""),
        sa.Column("prefix", sa.String(length=16), server_default=""),
        sa.Column("token_hash", sa.String(length=64), server_default=""),
        sa.Column("active", sa.Boolean(), server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_agent_tenant_name"),
    )
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])
    op.create_index("ix_agents_prefix", "agents", ["prefix"])
    op.add_column("findings", sa.Column("agent", sa.String(length=128), server_default=""))
    op.create_index("ix_findings_agent", "findings", ["agent"])


def downgrade():
    op.drop_index("ix_findings_agent", table_name="findings")
    op.drop_column("findings", "agent")
    op.drop_index("ix_agents_prefix", table_name="agents")
    op.drop_index("ix_agents_tenant_id", table_name="agents")
    op.drop_table("agents")
