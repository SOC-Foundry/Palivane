"""tenant alerting

Revision ID: d5a90b21e6f8
Revises: c3f8a1d05e27
Create Date: 2026-07-06 14:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd5a90b21e6f8'
down_revision: Union[str, None] = 'c3f8a1d05e27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('alert_webhook', sa.String(length=1024), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('alert_min_severity', sa.String(length=16), nullable=True, server_default='high'))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('alert_min_severity')
        batch_op.drop_column('alert_webhook')
