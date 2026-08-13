"""connector sync_state — incremental-scan watermark for content-scanning connectors

Slack message scanning keeps a per-channel last-message-ts map so each sync pulls only
new messages. Grant-inventory connectors leave it empty (they are stateless snapshots).

Revision ID: e8a0c2d4f6b3
Revises: d7f9b1c3e5a4
Create Date: 2026-08-13 20:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e8a0c2d4f6b3'
down_revision: Union[str, None] = 'd7f9b1c3e5a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('saas_connectors', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sync_state', sa.Text(), nullable=True,
                                      server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('saas_connectors', schema=None) as batch_op:
        batch_op.drop_column('sync_state')
