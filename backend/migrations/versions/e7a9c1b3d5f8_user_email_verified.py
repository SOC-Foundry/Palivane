"""users.email_verified (new-org signup mailbox verification)

Revision ID: e7a9c1b3d5f8
Revises: d6f8b0c2e4a6
Create Date: 2026-07-14

"""
from alembic import op
import sqlalchemy as sa

revision = "e7a9c1b3d5f8"
down_revision = "d6f8b0c2e4a6"
branch_labels = None
depends_on = None


def upgrade():
    # Default true so every EXISTING user stays able to log in; only new-org signups made
    # after this (with the email plane on) start unverified.
    op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False,
                                     server_default=sa.true()))


def downgrade():
    op.drop_column("users", "email_verified")
