"""drop tenants.siem_naming — the brand key had only one value left

The column let a tenant pin the SIEM sourcetype and S3 object paths to the
pre-rebrand product name while new tenants got "palivane". That name is gone
from the product, leaving exactly one valid value — a setting that could only
ever be a no-op while still costing a column, an API field, and a UI control.

SIEM emission now uses the "palivane" sourcetype and source unconditionally.

Revision ID: f1a3c5e7b9d2
Revises: e8a0c2d4f6b3
Create Date: 2026-08-21
"""

from alembic import op
import sqlalchemy as sa

revision = "f1a3c5e7b9d2"
down_revision = "e8a0c2d4f6b3"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as b:
        b.drop_column("siem_naming")


def downgrade():
    with op.batch_alter_table("tenants") as b:
        b.add_column(sa.Column("siem_naming", sa.String(16), server_default="palivane"))
