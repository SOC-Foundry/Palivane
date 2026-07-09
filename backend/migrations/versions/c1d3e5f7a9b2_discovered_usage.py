"""discovered_usage: shadow-AI discovery inventory store

Revision ID: c1d3e5f7a9b2
Revises: b3d5f7092c4e
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "c1d3e5f7a9b2"
down_revision = "b3d5f7092c4e"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "discovered_usage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("actor", sa.String(length=320), server_default=""),
        sa.Column("team", sa.String(length=128), server_default=""),
        sa.Column("tool", sa.String(length=128), server_default=""),
        sa.Column("domain", sa.String(length=255), server_default=""),
        sa.Column("category", sa.String(length=32), server_default=""),
        sa.Column("source", sa.String(length=16), server_default="log"),
        sa.Column("event_count", sa.Integer(), server_default="0"),
        sa.Column("sensitive_count", sa.Integer(), server_default="0"),
        sa.Column("max_risk", sa.Integer(), server_default="0"),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "actor", "tool", name="uq_usage_actor_tool"),
    )
    op.create_index("ix_discovered_usage_tenant_id", "discovered_usage", ["tenant_id"])
    op.create_index("ix_discovered_usage_actor", "discovered_usage", ["actor"])
    op.create_index("ix_discovered_usage_tool", "discovered_usage", ["tool"])
    op.create_index("ix_discovered_usage_last_seen", "discovered_usage", ["last_seen"])


def downgrade():
    op.drop_table("discovered_usage")
