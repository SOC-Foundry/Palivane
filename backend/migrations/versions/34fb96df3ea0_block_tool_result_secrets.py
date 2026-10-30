"""Block tool-result secrets: the org setting

`tenants.block_tool_result_secrets`: a confirmed secret in what an agent's tool returned is
stopped before it reaches the model, on the gateway and the Inference hooks, in monitor mode
too. On by default; an org whose repos keep fake vendor keys in test fixtures can turn it off.

Additive. Existing orgs get the default (on), which is the new behaviour.

Revision ID: 34fb96df3ea0
Revises: 1763cbaf8910
"""

import sqlalchemy as sa
from alembic import op

revision = "34fb96df3ea0"
down_revision = "1763cbaf8910"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("block_tool_result_secrets", sa.Boolean(), nullable=False,
                                       server_default=sa.true()))


def downgrade() -> None:
    op.drop_column("tenants", "block_tool_result_secrets")
