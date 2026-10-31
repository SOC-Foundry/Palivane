"""Weekly report: retry the admins it missed

`tenants.weekly_report_retry` (JSON, nullable): when a week's report reached some admins but
not others, who is left and the report text, so a later run sends it to them. Until now the
week counted as sent and they never got it.

Additive and nullable.

Revision ID: 098f19800b66
Revises: f115f9a37e03
"""

import sqlalchemy as sa
from alembic import op

revision = "098f19800b66"
down_revision = "f115f9a37e03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("weekly_report_retry", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "weekly_report_retry")
