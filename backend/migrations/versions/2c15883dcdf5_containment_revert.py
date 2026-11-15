"""containments: revert_since, so a containment can also put the agent's files back

app/containment.py. An admin asks for the agent's changes since a moment to be undone; the
device's hook sees `revert_since` in the containment answer, restores from its journal, and
reports what it did (`reverts`).

Revision ID: 2c15883dcdf5
Revises: 1384d3a95e4a
"""
import sqlalchemy as sa
from alembic import op

revision = "2c15883dcdf5"
down_revision = "1384d3a95e4a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("containments", sa.Column("revert_since", sa.DateTime(), nullable=True))
    op.add_column("containments", sa.Column("revert_by", sa.String(320), server_default=""))
    op.add_column("containments", sa.Column("reverts", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("containments", "reverts")
    op.drop_column("containments", "revert_by")
    op.drop_column("containments", "revert_since")
