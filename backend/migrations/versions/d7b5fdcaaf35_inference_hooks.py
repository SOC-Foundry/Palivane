"""Anthropic Inference hooks: per-tenant signing secrets and the denied-message ledger

Palivane can serve as a Claude Enterprise org's Inference hooks "AI security server"
(app/inference_hooks.py). The org's Standard Webhooks signing secret is stored sealed on the
tenant, with the previous one kept through a rotation. inference_hook_denials remembers the
hash of each user message a prompt was denied for, so the same content resent later in the
conversation is denied again; it is tenant-scoped, so it gets the same RLS policy as every
other tenant table (copied from f758200a1b4b).

Revision ID: d7b5fdcaaf35
Revises: 8c9b9484a3ed
"""

import sqlalchemy as sa
from alembic import op

revision = "d7b5fdcaaf35"
down_revision = "8c9b9484a3ed"
branch_labels = None
depends_on = None

_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade() -> None:
    op.add_column("tenants", sa.Column("inference_hook_secret", sa.String(512), server_default=""))
    op.add_column("tenants", sa.Column("inference_hook_secret_prev", sa.String(512), server_default=""))
    op.add_column("tenants", sa.Column("inference_hook_sig_failures", sa.Integer(), server_default="0"))
    op.add_column("tenants", sa.Column("inference_hook_last_sig_failure", sa.DateTime(), nullable=True))
    op.create_table(
        "inference_hook_denials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("session_id", sa.String(128), server_default=""),
        sa.Column("block_hash", sa.String(64), server_default=""),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "session_id", "block_hash", name="uq_inference_hook_denial"),
    )
    op.create_index("ix_inference_hook_denials_id", "inference_hook_denials", ["id"])
    op.create_index("ix_inference_hook_denials_tenant_id", "inference_hook_denials", ["tenant_id"])
    op.create_index("ix_inference_hook_denials_session_id", "inference_hook_denials", ["session_id"])
    op.create_index("ix_inference_hook_denials_created_at", "inference_hook_denials", ["created_at"])
    if op.get_bind().dialect.name == "postgresql":
        t = "inference_hook_denials"
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"CREATE POLICY tenant_isolation ON {t} "
                   f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        t = "inference_hook_denials"
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("inference_hook_denials")
    op.drop_column("tenants", "inference_hook_last_sig_failure")
    op.drop_column("tenants", "inference_hook_sig_failures")
    op.drop_column("tenants", "inference_hook_secret_prev")
    op.drop_column("tenants", "inference_hook_secret")
