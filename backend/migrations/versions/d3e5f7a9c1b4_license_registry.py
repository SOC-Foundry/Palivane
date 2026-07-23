"""license registry (vendor record of issued self-hosted licenses)

Revision ID: d3e5f7a9c1b4
Revises: c2d4f6a8b0e3
Create Date: 2026-07-22 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd3e5f7a9c1b4'
down_revision: Union[str, None] = 'c2d4f6a8b0e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'licenses',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('org', sa.String(length=320), nullable=False),
        sa.Column('plan', sa.String(length=16), nullable=False),
        sa.Column('seats', sa.Integer(), server_default='0'),
        sa.Column('issued_at', sa.DateTime()),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('contract_until', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='active'),
        sa.Column('renewed_at', sa.DateTime(), nullable=True),
        sa.Column('renew_count', sa.Integer(), server_default='0'),
        sa.Column('note', sa.String(length=512), server_default=''),
    )


def downgrade() -> None:
    op.drop_table('licenses')
