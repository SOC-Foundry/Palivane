"""secret_reach: what a leaked credential can reach, per secret fingerprint

app/reach.py. One row per secret the ledger has seen: the kind of credential, a sentence
on its scope, a severity hint, and for AWS keys the IAM user and policies the org's role
could read. Tenant-scoped, RLS like every tenant table.

Revision ID: 1384d3a95e4a
Revises: 4817515da948
"""
import sqlalchemy as sa
from alembic import op

revision = "1384d3a95e4a"
down_revision = "4817515da948"
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
        "secret_reach",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("secret_fp", sa.String(64), nullable=False),
        sa.Column("label", sa.String(64), server_default=""),
        sa.Column("kind", sa.String(24), server_default=""),
        sa.Column("scope", sa.String(500), server_default=""),
        sa.Column("severity", sa.String(16), server_default="medium"),
        sa.Column("source", sa.String(16), server_default="static"),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "secret_fp", name="uq_secret_reach_fp"),
    )
    op.create_index("ix_secret_reach_tenant_id", "secret_reach", ["tenant_id"])
    if op.get_bind().dialect.name == "postgresql":
        t = "secret_reach"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "secret_reach"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("secret_reach")
