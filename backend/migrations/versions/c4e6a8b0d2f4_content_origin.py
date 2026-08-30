"""content-origin matching — at-rest fingerprints + finding.origin

Revision ID: c4e6a8b0d2f4
Revises: b3d5f7a9c1e4
Create Date: 2026-08-29

"""
from alembic import op
import sqlalchemy as sa

revision = "c4e6a8b0d2f4"
down_revision = "b3d5f7a9c1e4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("origin", sa.JSON(), nullable=True))
    op.create_table(
        "content_fingerprints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("source", sa.String(32), server_default=""),
        sa.Column("ref", sa.String(512), server_default=""),
        sa.Column("title", sa.String(512), server_default=""),
        sa.Column("owner", sa.String(320), server_default=""),
        sa.Column("shingles", sa.JSON()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "source", "ref",
                            name="uq_fingerprint_tenant_source_ref"),
    )
    op.create_index("ix_content_fingerprints_tenant_id", "content_fingerprints", ["tenant_id"])
    op.create_index("ix_content_fingerprints_updated_at", "content_fingerprints", ["updated_at"])


def downgrade():
    op.drop_index("ix_content_fingerprints_updated_at", "content_fingerprints")
    op.drop_index("ix_content_fingerprints_tenant_id", "content_fingerprints")
    op.drop_table("content_fingerprints")
    op.drop_column("findings", "origin")
