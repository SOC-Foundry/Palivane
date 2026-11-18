"""ticket status sync: tracker status on the ticket, and a webhook secret

app/tickets.py. A Jira or ServiceNow ticket Palivane created can be resolved in either
place. `status` / `external_status` / `synced_at` remember what the tracker last said;
`external_id` is the Jira issue id or ServiceNow sys_id a transition needs. The tenant's
`ticket_webhook_secret` authenticates the inbound webhook (sealed like the API token).
Polling uses the same columns when the webhook never arrives.

Revision ID: 3d68f59e9ec9
Revises: c8f1a3e5b7d9
"""
import sqlalchemy as sa
from alembic import op

revision = "3d68f59e9ec9"
down_revision = "c8f1a3e5b7d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("ticket_webhook_secret", sa.String(2048), server_default=""))
    op.add_column("tickets", sa.Column("external_id", sa.String(64), server_default=""))
    op.add_column("tickets", sa.Column("status", sa.String(16), server_default="open"))
    op.add_column("tickets", sa.Column("external_status", sa.String(64), server_default=""))
    op.add_column("tickets", sa.Column("synced_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("tickets", "synced_at")
    op.drop_column("tickets", "external_status")
    op.drop_column("tickets", "status")
    op.drop_column("tickets", "external_id")
    op.drop_column("tenants", "ticket_webhook_secret")
