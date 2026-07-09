"""agent phase 2: role allow_commands + data_scopes, per-agent deny

Revision ID: c7e9a1b3d5f8
Revises: b6d8f0a2c4e7
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "c7e9a1b3d5f8"
down_revision = "b6d8f0a2c4e7"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("agent_roles", sa.Column("allow_commands", sa.String(length=2048), server_default=""))
    op.add_column("agent_roles", sa.Column("data_scopes", sa.String(length=512), server_default=""))
    op.add_column("agents", sa.Column("deny", sa.String(length=1024), server_default=""))


def downgrade():
    op.drop_column("agents", "deny")
    op.drop_column("agent_roles", "data_scopes")
    op.drop_column("agent_roles", "allow_commands")
