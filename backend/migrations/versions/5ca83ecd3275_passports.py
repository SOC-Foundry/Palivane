"""passports: signed, short-lived capability scopes for agents

app/passports.py. One row per passport issued: the agent, the scope (servers, tools,
commands, providers), who issued it, when it expires, when it was revoked, how often it
was presented. The token itself is a JWT the hook and the gateway verify; the row is what
makes a revoke immediate. Tenant-scoped, RLS like every tenant table.

Revision ID: 5ca83ecd3275
Revises: 2c15883dcdf5
"""
import sqlalchemy as sa
from alembic import op

revision = "5ca83ecd3275"
down_revision = "2c15883dcdf5"
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
        "passports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=False),
        sa.Column("agent_name", sa.String(128), server_default=""),
        sa.Column("jti", sa.String(32), nullable=False, unique=True),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.Column("note", sa.String(200), server_default=""),
        sa.Column("issued_by", sa.String(320), server_default=""),
        sa.Column("issued_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(320), server_default=""),
        sa.Column("uses", sa.Integer(), server_default="0"),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_passports_tenant_id", "passports", ["tenant_id"])
    op.create_index("ix_passports_expires_at", "passports", ["expires_at"])
    if op.get_bind().dialect.name == "postgresql":
        t = "passports"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "passports"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("passports")
