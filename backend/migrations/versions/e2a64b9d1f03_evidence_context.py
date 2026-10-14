"""evidence context: a masked excerpt around each match, opt-in per tenant

Revision ID: e2a64b9d1f03
Revises: c7f3a113c8e6
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa

revision = "e2a64b9d1f03"
down_revision = "c7f3a113c8e6"
branch_labels = None
depends_on = None


def upgrade():
    # Tri-state like store_content: NULL on every existing tenant, so they inherit
    # PALIVANE_EVIDENCE_CONTEXT (off) and any tenant that already stores prompt content, and
    # nothing is kept for anyone until an admin opts in.
    op.add_column("tenants", sa.Column("evidence_context", sa.Boolean(), nullable=True))
    # Nullable with no default: a metadata-only add on every supported database, no table rewrite.
    op.add_column("findings", sa.Column("evidence_context", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("findings", "evidence_context")
    op.drop_column("tenants", "evidence_context")
