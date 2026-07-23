"""finding recurrence folding (fingerprint + seen_count/last_seen)

Revision ID: e5f7a9b1c3d6
Revises: d3e5f7a9c1b4
Create Date: 2026-07-23 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5f7a9b1c3d6'
down_revision: Union[str, None] = 'd3e5f7a9c1b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('fingerprint', sa.String(length=64), server_default=''))
    op.add_column('findings', sa.Column('seen_count', sa.Integer(), server_default='1'))
    op.add_column('findings', sa.Column('last_seen', sa.DateTime(), nullable=True))
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'])
    # Existing rows: last activity = creation time.
    op.execute("UPDATE findings SET last_seen = created_at WHERE last_seen IS NULL")


def downgrade() -> None:
    op.drop_index('ix_findings_fingerprint', table_name='findings')
    op.drop_column('findings', 'last_seen')
    op.drop_column('findings', 'seen_count')
    op.drop_column('findings', 'fingerprint')
