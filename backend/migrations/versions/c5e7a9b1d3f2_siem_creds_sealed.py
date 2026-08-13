"""widen SIEM credential columns for at-rest sealing

siem_token and siem_s3_secret are now stored sealed (crypto.seal: Fernet + base64 +
enc:v1: tag), which expands the raw value ~1.5x plus fixed overhead — widen the columns
so a sealed max-length input still fits. Existing plaintext rows are left in place:
crypto.unseal passes untagged values through, and each row is sealed the next time the
tenant saves the credential.

Revision ID: c5e7a9b1d3f2
Revises: b4d6f8a0c2e7
Create Date: 2026-08-13 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c5e7a9b1d3f2'
down_revision: Union[str, None] = 'b4d6f8a0c2e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.alter_column('siem_token', existing_type=sa.String(length=1024),
                              type_=sa.String(length=2048), existing_nullable=True)
        batch_op.alter_column('siem_s3_secret', existing_type=sa.String(length=256),
                              type_=sa.String(length=512), existing_nullable=True)


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.alter_column('siem_token', existing_type=sa.String(length=2048),
                              type_=sa.String(length=1024), existing_nullable=True)
        batch_op.alter_column('siem_s3_secret', existing_type=sa.String(length=512),
                              type_=sa.String(length=256), existing_nullable=True)
