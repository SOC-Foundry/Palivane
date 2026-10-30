"""Exception requests: whether the actor was a claim

`exception_requests.claimed`: the requester's identity was named by the client (a fleet key's
per-request user) rather than proven by its key. An override can't relax policy for a claimed
actor, so such a request is refused at approval with an explanation instead of reading
"approved" and changing nothing.

Additive; existing rows default to not claimed (their approvals behave as before).

Revision ID: 540250ff34f0
Revises: ddf75044c25d
"""

import sqlalchemy as sa
from alembic import op

revision = "540250ff34f0"
down_revision = "ddf75044c25d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("exception_requests", sa.Column("claimed", sa.Boolean(), nullable=False,
                                                 server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("exception_requests", "claimed")
