"""tenant DPA acceptance record

Revision ID: a1b2c3d4e5f6
Revises: f7c2d43a8b1e
Create Date: 2026-07-07 00:15:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'f7c2d43a8b1e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dpa_version', sa.String(length=32), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('dpa_accepted_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('dpa_accepted_by', sa.String(length=320), nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('dpa_accepted_by')
        batch_op.drop_column('dpa_accepted_at')
        batch_op.drop_column('dpa_version')
