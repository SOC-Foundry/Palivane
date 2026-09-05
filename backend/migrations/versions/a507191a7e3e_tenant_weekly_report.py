"""tenant.weekly_report — weekly exec summary email

Revision ID: a507191a7e3e
Revises: 68812733d409
Create Date: 2026-09-05

"""
from alembic import op
import sqlalchemy as sa

revision = "a507191a7e3e"
down_revision = "68812733d409"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("weekly_report", sa.Boolean(), server_default=sa.text("false")))
    op.add_column("tenants", sa.Column("weekly_report_last", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("tenants", "weekly_report_last")
    op.drop_column("tenants", "weekly_report")
