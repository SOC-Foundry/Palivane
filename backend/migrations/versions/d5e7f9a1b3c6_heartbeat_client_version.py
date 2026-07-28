"""sensor_heartbeats: client + client_version (fleet build inventory)

Revision ID: d5e7f9a1b3c6
Revises: c4d6e8f0a2b5
Create Date: 2026-07-28 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd5e7f9a1b3c6'
down_revision: Union[str, None] = 'c4d6e8f0a2b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Parsed from the client User-Agent ("warden-hook/1.1.0") so the console can flag
    # devices running stale plumbing. Empty for pre-1.1 clients until they next report.
    op.add_column('sensor_heartbeats',
                  sa.Column('client', sa.String(length=48), server_default=''))
    op.add_column('sensor_heartbeats',
                  sa.Column('client_version', sa.String(length=24), server_default=''))


def downgrade() -> None:
    op.drop_column('sensor_heartbeats', 'client_version')
    op.drop_column('sensor_heartbeats', 'client')
