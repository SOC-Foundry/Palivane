"""per-tenant OIDC / SSO config

Revision ID: f6c8d0e24b53
Revises: e5b7c9d13a42
Create Date: 2026-06-30 22:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f6c8d0e24b53'
down_revision: Union[str, None] = 'e5b7c9d13a42'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'tenant_oidc',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('issuer', sa.String(length=512), nullable=True),
        sa.Column('client_id', sa.String(length=512), nullable=True),
        sa.Column('client_secret_encrypted', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('auto_provision', sa.Boolean(), nullable=True),
        sa.Column('allowed_domain', sa.String(length=256), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', name='uq_oidc_tenant'),
    )
    with op.batch_alter_table('tenant_oidc', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tenant_oidc_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tenant_oidc_tenant_id'), ['tenant_id'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('tenant_oidc', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tenant_oidc_tenant_id'))
        batch_op.drop_index(batch_op.f('ix_tenant_oidc_id'))
    op.drop_table('tenant_oidc')
