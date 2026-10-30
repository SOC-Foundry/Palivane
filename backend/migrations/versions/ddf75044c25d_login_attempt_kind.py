"""Login attempts: a kind per row

`login_attempts.kind` (login | signup | forgot | demo) gives each public endpoint that shares
the throttle table its own budget. Counted together, twenty demo visits or signups from one
address (an office NAT) locked everyone behind it out of login for the window.

Additive; existing rows are logins, and they age out within the throttle window anyway.

Revision ID: ddf75044c25d
Revises: 34fb96df3ea0
"""

import sqlalchemy as sa
from alembic import op

revision = "ddf75044c25d"
down_revision = "34fb96df3ea0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("login_attempts", sa.Column("kind", sa.String(16), nullable=False,
                                              server_default="login"))


def downgrade() -> None:
    op.drop_column("login_attempts", "kind")
