"""gateway usage metering + per-tenant rate limit

Revision ID: a7d9e1f34c60
Revises: f6c8d0e24b53
Create Date: 2026-07-01 09:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7d9e1f34c60'
down_revision: Union[str, None] = 'f6c8d0e24b53'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rate_limit', sa.Integer(), server_default='0', nullable=True))

    op.create_table(
        'gateway_usage',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('window_start', sa.DateTime(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'window_start', name='uq_usage_tenant_window'),
    )
    with op.batch_alter_table('gateway_usage', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_gateway_usage_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_gateway_usage_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_gateway_usage_window_start'), ['window_start'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('gateway_usage', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_gateway_usage_window_start'))
        batch_op.drop_index(batch_op.f('ix_gateway_usage_tenant_id'))
        batch_op.drop_index(batch_op.f('ix_gateway_usage_id'))
    op.drop_table('gateway_usage')
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('rate_limit')
