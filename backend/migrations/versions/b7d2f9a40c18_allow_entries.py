"""allow_entries: commands and paths an org has decided are fine, each with an expiry

Revision ID: b7d2f9a40c18
Revises: e2a64b9d1f03
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa

revision = "b7d2f9a40c18"
down_revision = "e2a64b9d1f03"
branch_labels = None
depends_on = None

# A new tenant-scoped table gets the same RLS policy as a9f1c3e5b7d0 (Postgres only; the rls CI job
# checks isolation against it).
_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade():
    op.create_table(
        "allow_entries",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), index=True, nullable=True),
        sa.Column("kind", sa.String(length=8), server_default="command"),
        sa.Column("pattern", sa.String(length=512), server_default=""),
        sa.Column("actor", sa.String(length=320), server_default=""),
        sa.Column("tool", sa.String(length=64), server_default=""),
        sa.Column("reason", sa.String(length=512), server_default=""),
        sa.Column("created_by", sa.String(length=320), server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False, index=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(length=320), server_default=""),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("hit_count", sa.Integer(), server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(), nullable=True),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE allow_entries ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE allow_entries FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY tenant_isolation ON allow_entries "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON allow_entries")
    op.drop_table("allow_entries")
