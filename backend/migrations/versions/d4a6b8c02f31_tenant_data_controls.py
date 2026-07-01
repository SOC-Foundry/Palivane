"""tenant data controls: judge consent + retention

Revision ID: d4a6b8c02f31
Revises: c3f5a2b8e910
Create Date: 2026-06-30 21:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4a6b8c02f31'
down_revision: Union[str, None] = 'c3f5a2b8e910'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('judge_enabled', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('retention_days', sa.Integer(), server_default='0', nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('retention_days')
        batch_op.drop_column('judge_enabled')
