"""tenant policy controls

Revision ID: e6b1c32f7a09
Revises: d5a90b21e6f8
Create Date: 2026-07-06 22:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e6b1c32f7a09'
down_revision: Union[str, None] = 'd5a90b21e6f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('gateway_enforce', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('gateway_block_severity', sa.String(length=16), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('mcp_block_severity', sa.String(length=16), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('sanctioned_ai_tools', sa.String(length=2048), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('tool_suppress', sa.String(length=2048), nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('tool_suppress')
        batch_op.drop_column('sanctioned_ai_tools')
        batch_op.drop_column('mcp_block_severity')
        batch_op.drop_column('gateway_block_severity')
        batch_op.drop_column('gateway_enforce')
