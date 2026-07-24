"""tenants: client_enforce (local capture planes monitor/enforce stance)

Revision ID: b2c4d6e8f0a3
Revises: a1b3c5d7e9f2
Create Date: 2026-07-24 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2c4d6e8f0a3'
down_revision: Union[str, None] = 'a1b3c5d7e9f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tri-state like gateway_enforce: NULL = inherit the global CLIENT_ENFORCE default.
    op.add_column('tenants', sa.Column('client_enforce', sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column('tenants', 'client_enforce')
