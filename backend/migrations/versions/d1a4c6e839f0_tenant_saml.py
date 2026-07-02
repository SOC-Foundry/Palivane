"""per-tenant SAML SSO config

Revision ID: d1a4c6e839f0
Revises: c9f1a3b572e8
Create Date: 2026-07-01 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd1a4c6e839f0'
down_revision: Union[str, None] = 'c9f1a3b572e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'tenant_saml',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('idp_entity_id', sa.String(length=512), nullable=True),
        sa.Column('idp_sso_url', sa.String(length=512), nullable=True),
        sa.Column('idp_x509_cert', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('auto_provision', sa.Boolean(), nullable=True),
        sa.Column('allowed_domain', sa.String(length=256), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', name='uq_saml_tenant'),
    )
    with op.batch_alter_table('tenant_saml', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tenant_saml_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tenant_saml_tenant_id'), ['tenant_id'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('tenant_saml', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tenant_saml_tenant_id'))
        batch_op.drop_index(batch_op.f('ix_tenant_saml_id'))
    op.drop_table('tenant_saml')
