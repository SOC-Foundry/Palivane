"""browser_extensions: per-device inventory of installed browser extensions

Palivane's Chrome/Edge extension can list the other extensions in its browser
(chrome.management, an optional permission the user or org opts into) and reports them to
/api/scan/browser-extensions. One row per (tenant, device, extension id), replaced on each
report. Tenant-scoped, so it gets the same RLS policy as every other tenant table (copied
from f758200a1b4b).

Revision ID: 5e0c77f236ab
Revises: d7b5fdcaaf35
"""

import sqlalchemy as sa
from alembic import op

revision = "5e0c77f236ab"
down_revision = "d7b5fdcaaf35"
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
        "browser_extensions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("device", sa.String(128), server_default=""),
        sa.Column("actor", sa.String(320), server_default=""),
        sa.Column("ext_id", sa.String(64), server_default=""),
        sa.Column("name", sa.String(255), server_default=""),
        sa.Column("version", sa.String(64), server_default=""),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true()),
        sa.Column("install_type", sa.String(32), server_default=""),
        sa.Column("host_access", sa.String(32), server_default=""),
        sa.Column("first_seen", sa.DateTime()),
        sa.Column("last_seen", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "device", "ext_id", name="uq_browser_ext_device"),
    )
    op.create_index("ix_browser_extensions_id", "browser_extensions", ["id"])
    op.create_index("ix_browser_extensions_tenant_id", "browser_extensions", ["tenant_id"])
    op.create_index("ix_browser_extensions_device", "browser_extensions", ["device"])
    op.create_index("ix_browser_extensions_actor", "browser_extensions", ["actor"])
    op.create_index("ix_browser_extensions_ext_id", "browser_extensions", ["ext_id"])
    op.create_index("ix_browser_extensions_last_seen", "browser_extensions", ["last_seen"])
    if op.get_bind().dialect.name == "postgresql":
        t = "browser_extensions"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "browser_extensions"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("browser_extensions")
