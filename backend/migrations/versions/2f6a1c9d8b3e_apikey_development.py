"""api_keys.development: a key whose captures are recorded as dismissed/expected

A machine that works on detection itself (fixtures, the hook source, a workflow piping
base64 into bash) fills the queue with its own test data; four detector PRs in two days
came from it (2026-11-12). Marked on the key in the console, never claimed by the client,
its captures are still recorded, so Fleet and the precision readout stay honest, but as
reviewed by the key: dismissed, expected, out of the queue, the alerts and the chains.

Revision ID: 2f6a1c9d8b3e
Revises: 98609b80f1be
"""
import sqlalchemy as sa
from alembic import op

revision = "2f6a1c9d8b3e"
down_revision = "98609b80f1be"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("development", sa.Boolean(), nullable=False,
                                        server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("api_keys", "development")
