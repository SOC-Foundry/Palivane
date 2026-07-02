"""user MFA (TOTP) fields

Revision ID: b8e0f2a461d7
Revises: a7d9e1f34c60
Create Date: 2026-07-01 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b8e0f2a461d7'
down_revision: Union[str, None] = 'a7d9e1f34c60'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mfa_enabled', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column('mfa_secret', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('mfa_recovery', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('mfa_recovery')
        batch_op.drop_column('mfa_secret')
        batch_op.drop_column('mfa_enabled')
