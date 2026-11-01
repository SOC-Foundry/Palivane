"""device_assets: per-device inventory of AI assets (MCP servers, extensions, agents, skills, plugins)

The posture scans already vetted what each device reports, but kept no record of WHAT was
on which device — so "which machines have this compromised MCP server / extension" had no
answer. One row per (tenant, device, kind, name); each posture report replaces that
device's set for the kind it covers. Tenant-scoped, so it gets the same RLS policy as
every other tenant table (copied from 5e0c77f236ab).

Revision ID: bf5595dff006
Revises: b0445ef199e2
"""

import sqlalchemy as sa
from alembic import op

revision = "bf5595dff006"
down_revision = "b0445ef199e2"
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
        "device_assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("device", sa.String(128), server_default=""),
        sa.Column("actor", sa.String(320), server_default=""),
        sa.Column("kind", sa.String(32), server_default=""),
        sa.Column("name", sa.String(255), server_default=""),
        sa.Column("version", sa.String(64), server_default=""),
        sa.Column("source", sa.String(255), server_default=""),
        sa.Column("extra", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime()),
        sa.Column("last_seen", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "device", "kind", "name", name="uq_device_asset"),
    )
    for col in ("tenant_id", "device", "actor", "kind", "name", "last_seen"):
        op.create_index(f"ix_device_assets_{col}", "device_assets", [col])
    if op.get_bind().dialect.name == "postgresql":
        t = "device_assets"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "device_assets"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("device_assets")
