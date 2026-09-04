"""tenant.self_justify — justified-proceed (Human-Firewall) toggle

Revision ID: b3d5f7a9c1e2
Revises: 9912bc2a5215
Create Date: 2026-09-04

"""
from alembic import op
import sqlalchemy as sa

revision = "b3d5f7a9c1e2"
down_revision = "9912bc2a5215"
branch_labels = None
depends_on = None


def upgrade():
    # Tri-state like redact_mode/client_enforce: NULL inherits PALIVANE_SELF_JUSTIFY.
    op.add_column("tenants", sa.Column("self_justify", sa.Boolean(), nullable=True))


def downgrade():
    op.drop_column("tenants", "self_justify")
