"""containments: an admin's "stop this now" on a person, device, agent or the org

app/containment.py. Every capture decision for an active containment's target answers block
and the gateway refuses its model calls, until it expires or is released. Tenant-scoped, so it
gets the same RLS policy as every other tenant table (copied from b8babc3c57a5).

Revision ID: d0d67dc07078
Revises: b8babc3c57a5
"""

import sqlalchemy as sa
from alembic import op

revision = "d0d67dc07078"
down_revision = "b8babc3c57a5"
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
        "containments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("scope", sa.String(16), server_default=""),
        sa.Column("target", sa.String(320), server_default=""),
        sa.Column("label", sa.String(320), server_default=""),
        sa.Column("reason", sa.String(500), server_default=""),
        sa.Column("created_by", sa.String(320), server_default=""),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("released_at", sa.DateTime(), nullable=True),
        sa.Column("released_by", sa.String(320), server_default=""),
        sa.Column("blocked", sa.Integer(), server_default="0"),
        sa.Column("last_blocked_at", sa.DateTime(), nullable=True),
    )
    for col in ("tenant_id", "expires_at", "released_at"):
        op.create_index(f"ix_containments_{col}", "containments", [col])
    if op.get_bind().dialect.name == "postgresql":
        t = "containments"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "containments"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("containments")
