"""developer_activity: who each protection plane covered, per calendar month

The meter behind per-developer pricing (app/developer_meter.py). One row per (tenant, month,
kind, person); the person is a keyed hash, never a name. Tenant-scoped, so it gets the same
RLS policy as every other tenant table (copied from bf5595dff006).

Revision ID: b8babc3c57a5
Revises: bf5595dff006
"""

import sqlalchemy as sa
from alembic import op

revision = "b8babc3c57a5"
down_revision = "bf5595dff006"
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
        "developer_activity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("month", sa.String(7), server_default=""),
        sa.Column("kind", sa.String(24), server_default=""),
        sa.Column("identity", sa.String(40), server_default=""),
        sa.Column("first_seen", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "month", "kind", "identity", name="uq_developer_activity"),
    )
    for col in ("tenant_id", "month", "kind"):
        op.create_index(f"ix_developer_activity_{col}", "developer_activity", [col])
    if op.get_bind().dialect.name == "postgresql":
        t = "developer_activity"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "developer_activity"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("developer_activity")
