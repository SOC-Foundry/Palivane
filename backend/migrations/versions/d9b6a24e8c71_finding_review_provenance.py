"""findings: who reviewed it, how, and why (the record the precision readout is built on)

Revision ID: d9b6a24e8c71
Revises: b7d2f9a40c18
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa

revision = "d9b6a24e8c71"
down_revision = "b7d2f9a40c18"
branch_labels = None
depends_on = None


def upgrade():
    # Nullable with no default: a metadata-only add on every supported database. Every existing
    # finding keeps NULL, which the readout reports as "reviewed before this was recorded" rather
    # than guessing how it was decided.
    op.add_column("findings", sa.Column("reviewed_at", sa.DateTime(), nullable=True))
    op.add_column("findings", sa.Column("reviewed_by", sa.String(length=320), nullable=True))
    op.add_column("findings", sa.Column("review_via", sa.String(length=16), nullable=True))
    op.add_column("findings", sa.Column("review_reason", sa.String(length=24), nullable=True))
    op.create_index("ix_findings_tenant_reviewed", "findings", ["tenant_id", "reviewed_at"])


def downgrade():
    op.drop_index("ix_findings_tenant_reviewed", table_name="findings")
    op.drop_column("findings", "review_reason")
    op.drop_column("findings", "review_via")
    op.drop_column("findings", "reviewed_by")
    op.drop_column("findings", "reviewed_at")
