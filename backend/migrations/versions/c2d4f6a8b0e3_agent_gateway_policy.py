"""agent gateway policy (per-agent rate limit + block-severity override)

Revision ID: c2d4f6a8b0e3
Revises: b1c3e5a7d9f2
Create Date: 2026-07-18 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c2d4f6a8b0e3'
down_revision: Union[str, None] = 'b1c3e5a7d9f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('agents', sa.Column('rate_limit', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('agents', sa.Column('block_severity', sa.String(length=16), nullable=True,
                                      server_default=''))


def downgrade() -> None:
    op.drop_column('agents', 'block_severity')
    op.drop_column('agents', 'rate_limit')
