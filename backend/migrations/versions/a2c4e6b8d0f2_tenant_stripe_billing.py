"""tenant Stripe billing ids — self-serve Team subscriptions

Revision ID: a2c4e6b8d0f2
Revises: f1a3c5e7b9d2
Create Date: 2026-08-25

"""
from alembic import op
import sqlalchemy as sa

revision = "a2c4e6b8d0f2"
down_revision = "f1a3c5e7b9d2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("stripe_customer_id", sa.String(64), server_default=""))
    op.add_column("tenants", sa.Column("stripe_subscription_id", sa.String(64), server_default=""))


def downgrade():
    op.drop_column("tenants", "stripe_subscription_id")
    op.drop_column("tenants", "stripe_customer_id")
