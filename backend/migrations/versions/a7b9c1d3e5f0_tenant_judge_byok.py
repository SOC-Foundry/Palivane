"""tenant judge BYOK — the org's own judge API key (provider, encrypted key, model)

Revision ID: a7b9c1d3e5f0
Revises: c2e4f6a8b0d3
Create Date: 2026-08-04
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a7b9c1d3e5f0'
down_revision: Union[str, None] = 'c2e4f6a8b0d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('judge_byok_provider', sa.String(length=16),
                                      nullable=True, server_default=''))
        batch_op.add_column(sa.Column('judge_byok_key_encrypted', sa.Text(),
                                      nullable=True, server_default=''))
        batch_op.add_column(sa.Column('judge_byok_model', sa.String(length=128),
                                      nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('judge_byok_model')
        batch_op.drop_column('judge_byok_key_encrypted')
        batch_op.drop_column('judge_byok_provider')
