"""instruction_taints: an actor received instruction-shaped content from an untrusted source

app/provenance.py. A row per inbound event (a tool result, advertised tool descriptions,
another agent's message) that carried prompt-injection-shaped threats, naming the source,
for a window; an action by that actor in the window that reaches a payoff stage gets the
"acting on an instruction nobody typed" signal. Tenant-scoped: RLS like every tenant table.

Revision ID: 5b9d2e7a4c18
Revises: 7c3e9a1d5b2f
"""
import sqlalchemy as sa
from alembic import op

revision = "5b9d2e7a4c18"
down_revision = "7c3e9a1d5b2f"
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
        "instruction_taints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor", sa.String(320), nullable=False, server_default=""),
        sa.Column("source", sa.String(320), nullable=False, server_default=""),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("expires_at", sa.DateTime()),
    )
    op.create_index("ix_instruction_taints_tenant_id", "instruction_taints", ["tenant_id"])
    op.create_index("ix_instruction_taints_actor", "instruction_taints", ["actor"])
    op.create_index("ix_instruction_taints_expires_at", "instruction_taints", ["expires_at"])
    if op.get_bind().dialect.name == "postgresql":
        t = "instruction_taints"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "instruction_taints"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("instruction_taints")
