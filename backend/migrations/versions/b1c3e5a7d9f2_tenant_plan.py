"""tenant plan (licensing tier: free | team | enterprise)

Revision ID: b1c3e5a7d9f2
Revises: a9f1c3e5b7d0
Create Date: 2026-07-18 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b1c3e5a7d9f2'
down_revision: Union[str, None] = 'a9f1c3e5b7d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('plan', sa.String(length=16), nullable=False,
                                       server_default='free'))
    # Grandfather every org that predates plans onto Enterprise — they signed up when all
    # features were unrestricted, so introducing tiers must not take anything away.
    op.execute("UPDATE tenants SET plan = 'enterprise'")


def downgrade() -> None:
    op.drop_column('tenants', 'plan')
