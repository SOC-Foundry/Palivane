"""domain capture: claimed tenant email domains + parked join requests

Revision ID: a3c5e7b9d1f2
Revises: e9a1c3b5d7f0
Create Date: 2026-07-13

"""
from alembic import op
import sqlalchemy as sa

revision = "a3c5e7b9d1f2"
down_revision = "e9a1c3b5d7f0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tenant_domains",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"),
                  index=True, nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("auto_approve", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("domain", name="uq_tenant_domain"),
    )
    op.create_table(
        "join_requests",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"),
                  index=True, nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False,
                  server_default="pending"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decided_by", sa.String(length=320), server_default=""),
        sa.UniqueConstraint("tenant_id", "email", name="uq_join_tenant_email"),
    )


def downgrade():
    op.drop_table("join_requests")
    op.drop_table("tenant_domains")
