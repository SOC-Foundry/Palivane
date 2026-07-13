"""tenant SIEM S3 delivery (bucket/prefix/region + write-only creds)

Revision ID: e9a1c3b5d7f0
Revises: d8f0b2c4e6a9
Create Date: 2026-07-13

"""
from alembic import op
import sqlalchemy as sa

revision = "e9a1c3b5d7f0"
down_revision = "b2d4f6a8c0e1"
branch_labels = None
depends_on = None


def upgrade():
    for col, size in (("siem_s3_bucket", 255), ("siem_s3_prefix", 255),
                      ("siem_s3_region", 32), ("siem_s3_key_id", 128), ("siem_s3_secret", 256)):
        op.add_column("tenants", sa.Column(col, sa.String(length=size), server_default=""))


def downgrade():
    for col in ("siem_s3_secret", "siem_s3_key_id", "siem_s3_region", "siem_s3_prefix", "siem_s3_bucket"):
        op.drop_column("tenants", col)
