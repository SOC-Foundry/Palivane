"""join_requests.email_verified (mailbox ownership proven via emailed confirm link)

Revision ID: d6f8b0c2e4a6
Revises: c5e7a9b1d3f5
Create Date: 2026-07-13

"""
from alembic import op
import sqlalchemy as sa

revision = "d6f8b0c2e4a6"
down_revision = "c5e7a9b1d3f5"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("join_requests", sa.Column("email_verified", sa.Boolean(), nullable=False,
                                             server_default=sa.false()))


def downgrade():
    op.drop_column("join_requests", "email_verified")
