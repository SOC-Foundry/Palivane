"""tenants.redact_mode (coaching mode — tri-state, NULL = inherit global)

NULL on every existing tenant, so they inherit PALIVANE_REDACT_MODE (off by default);
nobody's blocking behavior changes on deploy. An org opts into coaching explicitly.

Revision ID: d4f6a8c0e2b5
Revises: c8e0a2b4d6f9
Create Date: 2026-08-10 21:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4f6a8c0e2b5'
down_revision: Union[str, None] = 'c8e0a2b4d6f9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('redact_mode', sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column('tenants', 'redact_mode')
