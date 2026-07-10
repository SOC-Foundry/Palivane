"""user mfa_last_step (TOTP replay guard)

Revision ID: b2d4f6a8c0e1
Revises: d8f0b2c4e6a9
Create Date: 2026-07-10 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2d4f6a8c0e1'
down_revision: Union[str, None] = 'd8f0b2c4e6a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('mfa_last_step', sa.Integer(), nullable=False, server_default='0'))


def downgrade() -> None:
    op.drop_column('users', 'mfa_last_step')
