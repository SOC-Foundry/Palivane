"""shared_signatures: confirmed poisoned tool descriptions and servers, shared across orgs

app/sharedsigs.py. A global table (no tenant_id, so no RLS: it carries no org identity, only
digests, a masked sample and keyed reporter handles) plus the opt-in flag on tenants.

Revision ID: 4817515da948
Revises: a879f6464715
"""
import sqlalchemy as sa
from alembic import op

revision = "4817515da948"
down_revision = "a879f6464715"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("share_signatures", sa.Boolean(), nullable=False,
                                       server_default=sa.false()))
    op.create_table(
        "shared_signatures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(24), server_default=""),
        sa.Column("digest", sa.String(64), nullable=False, unique=True),
        sa.Column("sample", sa.String(200), server_default=""),
        sa.Column("reporters", sa.JSON(), nullable=True),
        sa.Column("reports", sa.Integer(), server_default="0"),
        sa.Column("status", sa.String(16), server_default="active"),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_shared_signatures_status", "shared_signatures", ["status"])


def downgrade() -> None:
    op.drop_table("shared_signatures")
    op.drop_column("tenants", "share_signatures")
