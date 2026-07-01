"""login attempts (brute-force throttle)

Revision ID: b7e3c1a9d240
Revises: a484dcc215e2
Create Date: 2026-06-30 20:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7e3c1a9d240'
down_revision: Union[str, None] = 'a484dcc215e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'login_attempts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('login_attempts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_login_attempts_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_login_attempts_email'), ['email'], unique=False)
        batch_op.create_index(batch_op.f('ix_login_attempts_ip'), ['ip'], unique=False)
        batch_op.create_index(batch_op.f('ix_login_attempts_created_at'), ['created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('login_attempts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_login_attempts_created_at'))
        batch_op.drop_index(batch_op.f('ix_login_attempts_ip'))
        batch_op.drop_index(batch_op.f('ix_login_attempts_email'))
        batch_op.drop_index(batch_op.f('ix_login_attempts_id'))
    op.drop_table('login_attempts')
