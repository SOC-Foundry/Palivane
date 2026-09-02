"""tenants.gateway_tokenize — per-org opt-in for gateway tokenization

Revision ID: 9912bc2a5215
Revises: 54b3d4b8a602
Create Date: 2026-09-02

"""
from alembic import op
import sqlalchemy as sa

revision = "9912bc2a5215"
down_revision = "54b3d4b8a602"
branch_labels = None
depends_on = None


def upgrade():
    # Tri-state like redact_mode and judge_enabled: NULL inherits GATEWAY_TOKENIZE, and a
    # value overrides it. Nullable Boolean rather than a flag, so one org can pilot the
    # feature without changing what every other org's provider receives.
    op.add_column("tenants", sa.Column("gateway_tokenize", sa.Boolean(), nullable=True))


def downgrade():
    op.drop_column("tenants", "gateway_tokenize")
