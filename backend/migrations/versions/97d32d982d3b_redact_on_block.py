"""Redact-on-block: the org setting, and the audit mark on a finding

`tenants.redact_on_block` is the org's choice for what a client may do when a message is
blocked only for values it can remove (secrets, personal data): `off`, `offer` (the person
chooses "send with these removed") or `auto` (a client that cannot ask may remove them
itself). NULL inherits the deployment default (PALIVANE_REDACT_ON_BLOCK, `offer`).

`findings.redacted_resend_at` records that the person sent a version of the blocked message
with those values removed. A timestamp only, never content.

Additive and nullable: existing rows and older clients are untouched.

Revision ID: 97d32d982d3b
Revises: 5e0c77f236ab
"""

import sqlalchemy as sa
from alembic import op

revision = "97d32d982d3b"
down_revision = "5e0c77f236ab"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("redact_on_block", sa.String(8), nullable=True))
    op.add_column("findings", sa.Column("redacted_resend_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "redacted_resend_at")
    op.drop_column("tenants", "redact_on_block")
