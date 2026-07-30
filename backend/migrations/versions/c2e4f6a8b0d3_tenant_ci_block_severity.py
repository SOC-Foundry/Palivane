"""tenants: ci_block_severity (per-org block threshold for CI-runner scans)

Empty on every existing tenant, so they inherit the global CI_BLOCK_SEVERITY (`critical`):
confirmed CI exposure fails a build, posture debt warns. Set it to "high" per org to run
the strict ratchet instead.

Revision ID: c2e4f6a8b0d3
Revises: a9c1e3b5d7f2
Create Date: 2026-07-30 19:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c2e4f6a8b0d3'
down_revision: Union[str, None] = 'a9c1e3b5d7f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('ci_block_severity', sa.String(16),
                                       nullable=True, server_default=''))


def downgrade() -> None:
    op.drop_column('tenants', 'ci_block_severity')
