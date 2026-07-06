"""tenant mcp allowlist

Revision ID: b7e2f1a3c9d4
Revises: 0da9f945dbb6
Create Date: 2026-07-06 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7e2f1a3c9d4'
down_revision: Union[str, None] = '0da9f945dbb6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mcp_allowed_servers', sa.String(length=1024),
                                      nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('mcp_allowed_servers')
