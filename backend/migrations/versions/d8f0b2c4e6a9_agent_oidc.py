"""agent workload identity (OIDC): tenant issuer/jwks/audience + agent oidc_subject

Revision ID: d8f0b2c4e6a9
Revises: c7e9a1b3d5f8
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "d8f0b2c4e6a9"
down_revision = "c7e9a1b3d5f8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("agent_oidc_issuer", sa.String(length=512), server_default=""))
    op.add_column("tenants", sa.Column("agent_oidc_jwks", sa.String(length=512), server_default=""))
    op.add_column("tenants", sa.Column("agent_oidc_audience", sa.String(length=255), server_default=""))
    op.add_column("agents", sa.Column("oidc_subject", sa.String(length=320), server_default=""))
    op.create_index("ix_agents_oidc_subject", "agents", ["oidc_subject"])


def downgrade():
    op.drop_index("ix_agents_oidc_subject", table_name="agents")
    op.drop_column("agents", "oidc_subject")
    op.drop_column("tenants", "agent_oidc_audience")
    op.drop_column("tenants", "agent_oidc_jwks")
    op.drop_column("tenants", "agent_oidc_issuer")
