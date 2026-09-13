"""analyst_enabled — opt-in for the read-only AI analyst

The AI analyst sends a finding's redacted context to the tenant's LLM provider, so it is
OFF by default: this adds a per-tenant boolean that an admin flips on in Settings before the
Investigate button (and the endpoint) will run. Random revision id per the migration-ids
note; single head pinned.
"""
from alembic import op
import sqlalchemy as sa

revision = "0be77fbc37f7"
down_revision = "de230cf4cf7a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("analyst_enabled", sa.Boolean(),
                                       nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("tenants", "analyst_enabled")
