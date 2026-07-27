"""trustworthy enforcement: staged enforce overrides, sensor heartbeats, exception queue

- policy_overrides.enforce: per-user/group/tool monitor|enforce stance (NULL = inherit)
- api_keys.last_failed_at: revoked key still being presented (fleet visibility)
- sensor_heartbeats: last-seen per (actor, plane, tool) — fleet health
- exception_requests: block-screen exception queue with review state

Revision ID: c4d6e8f0a2b5
Revises: b2c4d6e8f0a3
Create Date: 2026-07-27 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c4d6e8f0a2b5'
down_revision: Union[str, None] = 'b2c4d6e8f0a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# New tenant-scoped tables get the same RLS policy as a9f1c3e5b7d0 (Postgres only).
_RLS_TABLES = ["sensor_heartbeats", "exception_requests"]
_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade() -> None:
    op.add_column('policy_overrides', sa.Column('enforce', sa.Boolean(), nullable=True))
    op.add_column('api_keys', sa.Column('last_failed_at', sa.DateTime(), nullable=True))

    op.create_table(
        'sensor_heartbeats',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'),
                  index=True, nullable=True),
        sa.Column('actor', sa.String(length=320), server_default=''),
        sa.Column('plane', sa.String(length=32), server_default=''),
        sa.Column('tool', sa.String(length=64), server_default=''),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True, index=True),
        sa.Column('count', sa.Integer(), server_default='0'),
        sa.UniqueConstraint('tenant_id', 'actor', 'plane', 'tool',
                            name='uq_heartbeat_scope'),
    )
    op.create_table(
        'exception_requests',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'),
                  index=True, nullable=True),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('actor', sa.String(length=320), server_default=''),
        sa.Column('destination', sa.String(length=2048), server_default=''),
        sa.Column('categories', sa.String(length=512), server_default=''),
        sa.Column('reason', sa.String(length=2000), server_default=''),
        sa.Column('status', sa.String(length=16), server_default='pending', index=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by', sa.String(length=320), server_default=''),
        sa.Column('resolution_note', sa.String(length=512), server_default=''),
        sa.Column('applied_override_id', sa.Integer(), nullable=True),
    )

    if op.get_bind().dialect.name == "postgresql":
        for t in _RLS_TABLES:
            op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                       f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for t in _RLS_TABLES:
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
    op.drop_table('exception_requests')
    op.drop_table('sensor_heartbeats')
    op.drop_column('api_keys', 'last_failed_at')
    op.drop_column('policy_overrides', 'enforce')
