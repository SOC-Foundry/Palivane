"""per-tenant admin audit log

Revision ID: c9f1a3b572e8
Revises: b8e0f2a461d7
Create Date: 2026-07-01 11:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c9f1a3b572e8'
down_revision: Union[str, None] = 'b8e0f2a461d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('actor', sa.String(length=320), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=True),
        sa.Column('target', sa.String(length=320), nullable=True),
        sa.Column('detail', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_log_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_created_at'), ['created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_log_created_at'))
        batch_op.drop_index(batch_op.f('ix_audit_log_tenant_id'))
        batch_op.drop_index(batch_op.f('ix_audit_log_id'))
    op.drop_table('audit_log')
