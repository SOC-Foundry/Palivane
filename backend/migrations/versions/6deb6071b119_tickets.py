"""tickets: Jira / ServiceNow tickets for exposures and containments, plus the tracker config

app/tickets.py. Six tenant columns hold the org's tracker (kind, URL, user, sealed token,
project/table, issue type); the tickets table remembers which exposure or containment
already has a ticket, so the tracker is asked once per row. Tenant-scoped, RLS like every
tenant table.

Revision ID: 6deb6071b119
Revises: 6a2c8e4f1b9d
"""
import sqlalchemy as sa
from alembic import op

revision = "6deb6071b119"
down_revision = "6a2c8e4f1b9d"
branch_labels = None
depends_on = None

_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade() -> None:
    op.add_column("tenants", sa.Column("ticket_kind", sa.String(16), server_default=""))
    op.add_column("tenants", sa.Column("ticket_url", sa.String(1024), server_default=""))
    op.add_column("tenants", sa.Column("ticket_user", sa.String(320), server_default=""))
    op.add_column("tenants", sa.Column("ticket_token", sa.String(2048), server_default=""))
    op.add_column("tenants", sa.Column("ticket_project", sa.String(64), server_default=""))
    op.add_column("tenants", sa.Column("ticket_issue_type", sa.String(64), server_default=""))
    op.create_table(
        "tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("kind", sa.String(16), server_default=""),
        sa.Column("ref_id", sa.Integer(), nullable=False),
        sa.Column("tracker", sa.String(16), server_default=""),
        sa.Column("key", sa.String(64), server_default=""),
        sa.Column("url", sa.String(1024), server_default=""),
        sa.Column("created_by", sa.String(320), server_default=""),
        sa.Column("created_at", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "kind", "ref_id", name="uq_ticket_ref"),
    )
    op.create_index("ix_tickets_tenant_id", "tickets", ["tenant_id"])
    if op.get_bind().dialect.name == "postgresql":
        t = "tickets"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "tickets"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("tickets")
    for col in ("ticket_issue_type", "ticket_project", "ticket_token", "ticket_user",
                "ticket_url", "ticket_kind"):
        op.drop_column("tenants", col)
