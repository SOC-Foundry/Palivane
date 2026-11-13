"""actor_hours: when each actor is usually active, one count per hour of the week

Feeds containment's quiet warning (app/activity.py): silence at an hour the person is
never around is not a sign they stripped the hooks. Tenant-scoped, so it gets the same
RLS policy as every other tenant table (copied from d0d67dc07078).

Revision ID: 7c3e9a1d5b2f
Revises: 2f6a1c9d8b3e
"""
import sqlalchemy as sa
from alembic import op

revision = "7c3e9a1d5b2f"
down_revision = "2f6a1c9d8b3e"
branch_labels = None
depends_on = None

_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade() -> None:
    op.create_table(
        "actor_hours",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor", sa.String(320), nullable=False, server_default=""),
        sa.Column("slot", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "actor", "slot", name="uq_actor_hours_slot"),
    )
    op.create_index("ix_actor_hours_tenant_id", "actor_hours", ["tenant_id"])
    op.create_index("ix_actor_hours_actor", "actor_hours", ["actor"])
    if op.get_bind().dialect.name == "postgresql":
        t = "actor_hours"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "actor_hours"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("actor_hours")
