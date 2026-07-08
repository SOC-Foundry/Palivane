"""tenant SIEM forwarding

Revision ID: a2c4e6081b3d
Revises: f1a2b3c4d5e6
Create Date: 2026-07-08 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a2c4e6081b3d'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('siem_url', sa.String(length=1024), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('siem_token', sa.String(length=1024), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('siem_min_severity', sa.String(length=16), nullable=True, server_default='high'))
        batch_op.add_column(sa.Column('siem_format', sa.String(length=16), nullable=True, server_default='json'))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('siem_format')
        batch_op.drop_column('siem_min_severity')
        batch_op.drop_column('siem_token')
        batch_op.drop_column('siem_url')
