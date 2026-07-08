"""tenant custom PII patterns

Revision ID: b3d5f7092c4e
Revises: a2c4e6081b3d
Create Date: 2026-07-08 14:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3d5f7092c4e'
down_revision: Union[str, None] = 'a2c4e6081b3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('custom_pii_patterns', sa.String(length=4096), nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('custom_pii_patterns')
