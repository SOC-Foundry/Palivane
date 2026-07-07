"""sensor quota split: usage kind + per-tenant ingest rate limit

Revision ID: f7c2d43a8b1e
Revises: e6b1c32f7a09
Create Date: 2026-07-06 23:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f7c2d43a8b1e'
down_revision: Union[str, None] = 'e6b1c32f7a09'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('ingest_rate_limit', sa.Integer(), nullable=True, server_default='0'))
    # Split the usage counter by kind (gateway vs sensor ingest); rebuild the unique key.
    with op.batch_alter_table('gateway_usage', schema=None) as batch_op:
        batch_op.add_column(sa.Column('kind', sa.String(length=16), nullable=False, server_default='gateway'))
        batch_op.drop_constraint('uq_usage_tenant_window', type_='unique')
        batch_op.create_unique_constraint('uq_usage_tenant_window_kind',
                                          ['tenant_id', 'window_start', 'kind'])


def downgrade() -> None:
    with op.batch_alter_table('gateway_usage', schema=None) as batch_op:
        batch_op.drop_constraint('uq_usage_tenant_window_kind', type_='unique')
        batch_op.create_unique_constraint('uq_usage_tenant_window', ['tenant_id', 'window_start'])
        batch_op.drop_column('kind')
    op.drop_column('tenants', 'ingest_rate_limit')
