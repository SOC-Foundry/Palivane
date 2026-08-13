"""tenant S3 delivery via IAM role (STS AssumeRole)

Adds the cross-account role config for S3 delivery: the customer's role ARN and the
per-tenant external ID their trust policy pins (confused-deputy guard). Preferred over
the static key pair — no long-lived AWS secret stored, and the customer can revoke by
editing their own trust policy.

Revision ID: d7f9b1c3e5a4
Revises: c5e7a9b1d3f2
Create Date: 2026-08-13 14:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd7f9b1c3e5a4'
down_revision: Union[str, None] = 'c5e7a9b1d3f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('siem_s3_role_arn', sa.String(length=512),
                                      nullable=True, server_default=''))
        batch_op.add_column(sa.Column('siem_s3_external_id', sa.String(length=64),
                                      nullable=True, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('siem_s3_external_id')
        batch_op.drop_column('siem_s3_role_arn')
