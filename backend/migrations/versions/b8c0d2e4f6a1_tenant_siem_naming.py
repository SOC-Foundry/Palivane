"""tenant siem_naming — brand key used in SIEM sourcetype + S3 object paths

Existing tenants are backfilled to "warden" (their Splunk dashboards key on the
warden:finding sourcetype and their S3 pipelines point at warden/findings/) — the
server_default does that at ADD COLUMN time. New tenants get "palivane" from the
ORM default; they can switch either way in Settings → SIEM.

Revision ID: b8c0d2e4f6a1
Revises: a7b9c1d3e5f0
Create Date: 2026-08-05

"""
from alembic import op
import sqlalchemy as sa

revision = "b8c0d2e4f6a1"
down_revision = "a7b9c1d3e5f0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("siem_naming", sa.String(16), server_default="warden"))


def downgrade():
    op.drop_column("tenants", "siem_naming")
