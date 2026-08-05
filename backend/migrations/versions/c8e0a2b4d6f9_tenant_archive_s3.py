"""tenant raw event archival to S3 (enable + raw-content opt-in + daily byte budget)

Revision ID: c8e0a2b4d6f9
Revises: b8c0d2e4f6a1
Create Date: 2026-08-05

"""
from alembic import op
import sqlalchemy as sa

revision = "c8e0a2b4d6f9"
down_revision = "b8c0d2e4f6a1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("archive_s3_enabled", sa.Boolean(),
                                       server_default=sa.false(), nullable=False))
    op.add_column("tenants", sa.Column("archive_s3_raw_content", sa.Boolean(),
                                       server_default=sa.false(), nullable=False))
    op.add_column("tenants", sa.Column("archive_s3_daily_mb", sa.Integer(),
                                       server_default="0", nullable=False))


def downgrade():
    for col in ("archive_s3_daily_mb", "archive_s3_raw_content", "archive_s3_enabled"):
        op.drop_column("tenants", col)
