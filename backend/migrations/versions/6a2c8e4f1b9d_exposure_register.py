"""exposure_register: regulated data that reached a provider, with the regulatory clock

app/exposures.py. One row per finding whose regulated class (personal or health data)
actually left on a live egress surface: the regime, its deadline, who sent it, where it
went, and the status a person works it through. Tenant-scoped, RLS like every tenant table.

Revision ID: 6a2c8e4f1b9d
Revises: 3d7f9b1e6a24
"""
import sqlalchemy as sa
from alembic import op

revision = "6a2c8e4f1b9d"
down_revision = "3d7f9b1e6a24"
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
        "exposure_register",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("classes", sa.String(128), server_default=""),
        sa.Column("regime", sa.String(64), server_default=""),
        sa.Column("actor", sa.String(320), server_default=""),
        sa.Column("destination", sa.String(128), server_default=""),
        sa.Column("surface", sa.String(32), server_default=""),
        sa.Column("opened_at", sa.DateTime()),
        sa.Column("deadline_at", sa.DateTime()),
        sa.Column("status", sa.String(16), server_default="open"),
        sa.Column("note", sa.String(1000), server_default=""),
        sa.Column("acknowledged_by", sa.String(320), server_default=""),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("notified_at", sa.DateTime(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("closed_reason", sa.String(32), server_default=""),
        sa.UniqueConstraint("tenant_id", "finding_id", name="uq_exposure_finding"),
    )
    op.create_index("ix_exposure_register_tenant_id", "exposure_register", ["tenant_id"])
    op.create_index("ix_exposure_register_deadline_at", "exposure_register", ["deadline_at"])
    if op.get_bind().dialect.name == "postgresql":
        t = "exposure_register"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "exposure_register"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("exposure_register")
