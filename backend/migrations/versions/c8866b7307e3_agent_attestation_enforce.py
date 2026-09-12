"""tenant.agent_attestation_enforce — block unattested agent tool calls

When agent OIDC is configured, optionally block tool calls whose acting agent isn't
OIDC-attested (came in on a bearer ag_ token, or none). Off by default (flag only).
Nullable/additive; random revision id per the migration-ids note; single head pinned.
"""
from alembic import op
import sqlalchemy as sa

revision = "c8866b7307e3"
down_revision = "7f131987beb2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("agent_attestation_enforce", sa.Boolean(),
                                       nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("tenants", "agent_attestation_enforce")
