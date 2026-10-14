"""tenant.ask_on_warn — the ASK verdict toggle

Revision ID: c7f3a113c8e6
Revises: 0be77fbc37f7
Create Date: 2026-10-13

"""
from alembic import op
import sqlalchemy as sa

revision = "c7f3a113c8e6"
down_revision = "0be77fbc37f7"
branch_labels = None
depends_on = None


def upgrade():
    # Tri-state like self_justify/redact_mode: NULL on every existing tenant, so they
    # inherit PALIVANE_ASK_ON_WARN (off by default) and nothing changes until an admin opts in.
    op.add_column("tenants", sa.Column("ask_on_warn", sa.Boolean(), nullable=True))


def downgrade():
    op.drop_column("tenants", "ask_on_warn")
