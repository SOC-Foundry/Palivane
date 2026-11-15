"""commit_attestations: which commits were AI-assisted, and were they checked

app/attest.py. One row per commit a device registered after `palivane-hook git-install`
put the trailers in: the sha, repo and author, what the agent did in the window, and how
many findings Palivane raised for that person in it. Tenant-scoped, RLS like every tenant
table.

Revision ID: a879f6464715
Revises: 6deb6071b119
"""
import sqlalchemy as sa
from alembic import op

revision = "a879f6464715"
down_revision = "6deb6071b119"
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
        "commit_attestations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("sha", sa.String(64), nullable=False),
        sa.Column("repo", sa.String(300), server_default=""),
        sa.Column("branch", sa.String(120), server_default=""),
        sa.Column("author", sa.String(320), server_default=""),
        sa.Column("actor", sa.String(320), server_default=""),
        sa.Column("subject", sa.String(200), server_default=""),
        sa.Column("agent", sa.String(120), server_default=""),
        sa.Column("tool_calls", sa.Integer(), server_default="0"),
        sa.Column("files", sa.Integer(), server_default="0"),
        sa.Column("blocked", sa.Integer(), server_default="0"),
        sa.Column("findings", sa.Integer(), server_default="0"),
        sa.Column("finding_ids", sa.JSON(), nullable=True),
        sa.Column("window_start", sa.DateTime(), nullable=True),
        sa.Column("window_end", sa.DateTime(), nullable=True),
        sa.Column("token", sa.String(64), server_default=""),
        sa.Column("created_at", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "sha", name="uq_attest_sha"),
    )
    op.create_index("ix_commit_attestations_tenant_id", "commit_attestations", ["tenant_id"])
    op.create_index("ix_commit_attestations_created_at", "commit_attestations", ["created_at"])
    if op.get_bind().dialect.name == "postgresql":
        t = "commit_attestations"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "commit_attestations"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("commit_attestations")
