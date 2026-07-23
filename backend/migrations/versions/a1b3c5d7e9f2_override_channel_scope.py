"""policy overrides: optional tool/channel scope

Revision ID: a1b3c5d7e9f2
Revises: f0a2c4e6b8d1
Create Date: 2026-07-23 14:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b3c5d7e9f2'
down_revision: Union[str, None] = 'f0a2c4e6b8d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch mode: SQLite can't ALTER constraints in place (Postgres passes through).
    with op.batch_alter_table('policy_overrides') as batch:
        batch.add_column(sa.Column('channel', sa.String(length=64), server_default=''))
        batch.drop_constraint('uq_override_scope_match', type_='unique')
        batch.create_unique_constraint('uq_override_scope_match',
                                       ['tenant_id', 'scope', 'match', 'channel'])


def downgrade() -> None:
    with op.batch_alter_table('policy_overrides') as batch:
        batch.drop_constraint('uq_override_scope_match', type_='unique')
        batch.create_unique_constraint('uq_override_scope_match',
                                       ['tenant_id', 'scope', 'match'])
        batch.drop_column('channel')
