"""per-tenant upstream provider config

Revision ID: c3f5a2b8e910
Revises: b7e3c1a9d240
Create Date: 2026-06-30 20:40:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3f5a2b8e910'
down_revision: Union[str, None] = 'b7e3c1a9d240'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'tenant_upstreams',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('provider', sa.String(length=32), nullable=False),
        sa.Column('base_url', sa.String(length=512), nullable=True),
        sa.Column('key_encrypted', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'provider', name='uq_upstream_tenant_provider'),
    )
    with op.batch_alter_table('tenant_upstreams', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tenant_upstreams_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tenant_upstreams_tenant_id'), ['tenant_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('tenant_upstreams', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tenant_upstreams_tenant_id'))
        batch_op.drop_index(batch_op.f('ix_tenant_upstreams_id'))
    op.drop_table('tenant_upstreams')
