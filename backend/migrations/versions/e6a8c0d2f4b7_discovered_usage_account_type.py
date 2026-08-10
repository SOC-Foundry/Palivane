"""discovered_usage.account_type (personal vs corporate account distinction)

Empty on existing rows; it's re-derived on the next capture/log upsert for each actor, so
the inventory backfills naturally as usage continues.

Revision ID: e6a8c0d2f4b7
Revises: d4f6a8c0e2b5
Create Date: 2026-08-10 22:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e6a8c0d2f4b7'
down_revision: Union[str, None] = 'd4f6a8c0e2b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('discovered_usage', sa.Column('account_type', sa.String(16),
                                                nullable=True, server_default=''))


def downgrade() -> None:
    op.drop_column('discovered_usage', 'account_type')
