"""tenant_lanes: a private upstream per provider for the data classes the org routes

app/lanes.py. A request whose verdict carries one of the lane's data classes goes to the
lane (the org's zero-retention or self-hosted endpoint) instead of being blocked; the
finding records where it went. Tenant-scoped: RLS like every tenant table.

Revision ID: 3d7f9b1e6a24
Revises: 8e4a6c2f9d17
"""
import sqlalchemy as sa
from alembic import op

revision = "3d7f9b1e6a24"
down_revision = "8e4a6c2f9d17"
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
        "tenant_lanes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("label", sa.String(128), server_default=""),
        sa.Column("base_url", sa.String(512), server_default=""),
        sa.Column("key_encrypted", sa.Text(), server_default=""),
        sa.Column("classes", sa.String(256), server_default=""),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "provider", name="uq_tenant_lane_provider"),
    )
    op.create_index("ix_tenant_lanes_tenant_id", "tenant_lanes", ["tenant_id"])
    if op.get_bind().dialect.name == "postgresql":
        t = "tenant_lanes"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "tenant_lanes"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("tenant_lanes")
