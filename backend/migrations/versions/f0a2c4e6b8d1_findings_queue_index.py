"""findings queue index (tenant_id, last_seen) — indexed newest-activity-first sort

Revision ID: f0a2c4e6b8d1
Revises: e5f7a9b1c3d6
Create Date: 2026-07-23 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'f0a2c4e6b8d1'
down_revision: Union[str, None] = 'e5f7a9b1c3d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index('ix_findings_tenant_last_seen', 'findings', ['tenant_id', 'last_seen'])


def downgrade() -> None:
    op.drop_index('ix_findings_tenant_last_seen', table_name='findings')
