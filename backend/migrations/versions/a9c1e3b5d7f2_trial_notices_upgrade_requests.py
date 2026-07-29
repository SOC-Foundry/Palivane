"""tenants.trial_notice + upgrade_requests (trial lifecycle emails, in-console upgrade path)

trial_notice backfills to '' so every existing trial tenant is treated as "nothing sent
yet" — the notice loop then sends only the stage currently due (one email, not a backlog).

Revision ID: a9c1e3b5d7f2
Revises: e6f8a0b2c4d7
Create Date: 2026-07-29 18:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a9c1e3b5d7f2'
down_revision: Union[str, None] = 'e6f8a0b2c4d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('trial_notice', sa.String(16),
                                       nullable=False, server_default=''))
    op.create_table(
        'upgrade_requests',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'),
                  nullable=False, index=True),
        sa.Column('plan', sa.String(16), nullable=False),
        sa.Column('seats', sa.Integer(), server_default='0'),
        sa.Column('contact', sa.String(320), server_default=''),
        sa.Column('note', sa.String(2000), server_default=''),
        sa.Column('status', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('upgrade_requests')
    op.drop_column('tenants', 'trial_notice')
