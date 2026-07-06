"""tenant supply-chain lists

Revision ID: c3f8a1d05e27
Revises: b7e2f1a3c9d4
Create Date: 2026-07-06 14:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3f8a1d05e27'
down_revision: Union[str, None] = 'b7e2f1a3c9d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('ide_ext_allowed', sa.String(length=2048), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('ide_ext_denylist', sa.String(length=2048), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('dep_denylist', sa.String(length=2048), nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('dep_denylist')
        batch_op.drop_column('ide_ext_denylist')
        batch_op.drop_column('ide_ext_allowed')
