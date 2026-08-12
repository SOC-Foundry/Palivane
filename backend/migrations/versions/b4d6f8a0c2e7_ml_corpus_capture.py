"""ml corpus capture — tenant opt-in flag + labeled-corpus staging table

Consented capture pipeline for the ML classifier's real training corpus (the go/no-go
gate in docs/ml-classifier-baseline.md). tenants.ml_capture is an explicit per-tenant
opt-in (default false, no global inherit); corpus_samples stages sampled prompts with
the regex verdict as a weak label and a NULL analyst label until a human sets one.

Revision ID: b4d6f8a0c2e7
Revises: a1c3e5b7d9f2
Create Date: 2026-08-12
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "b4d6f8a0c2e7"
down_revision: Union[str, None] = "a1c3e5b7d9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("ml_capture", sa.Boolean(),
                                       server_default=sa.false()))
    op.create_table(
        "corpus_samples",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"),
                  index=True, nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True, index=True),
        sa.Column("channel", sa.String(64), server_default=""),
        sa.Column("surface", sa.String(32), server_default="llm_io"),
        sa.Column("content", sa.Text(), server_default=""),
        sa.Column("regex_severity", sa.String(16), server_default=""),
        sa.Column("regex_score", sa.Integer(), server_default="0"),
        sa.Column("weak_label", sa.String(16), server_default=""),
        sa.Column("label", sa.String(16), nullable=True),   # NULL = unlabeled
        sa.Column("labeled_by", sa.String(320), server_default=""),
        sa.Column("labeled_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_corpus_tenant_created", "corpus_samples",
                    ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_corpus_tenant_created", table_name="corpus_samples")
    op.drop_table("corpus_samples")
    op.drop_column("tenants", "ml_capture")
