"""Durable SIEM/alert outbox, and RLS that fails closed

Revision ID: c8f1a3e5b7d9
Revises: 5ca83ecd3275
Create Date: 2026-11-18

Delivery used to be a best-effort thread-pool submit: a saturated pool dropped the
event, and a restart dropped anything still queued. Findings now insert a row into
delivery_outbox in the capture transaction. A lifespan loop claims rows across
instances (conditional update), retries with backoff, and dead-letters what does
not go through. delivery_cursors keeps last success / failure after delivered rows
are pruned.

RLS used to treat an unset app.tenant_id as "see every tenant". A request or job
that forgot bind_tenant therefore read and wrote across tenants. The policy now
fails closed unless app.tenant_id names one tenant, or app.cross_tenant is exactly
'on' (set only by database.allow_cross_tenant, which records why). NULL-tenant
global rows stay visible to a bound tenant and to an explicit bypass, and to
nobody else.

SQLite has no RLS; the table creates still run. The policy rewrite is Postgres only.
"""
from alembic import op
import sqlalchemy as sa

revision = "c8f1a3e5b7d9"
down_revision = "5ca83ecd3275"
branch_labels = None
depends_on = None

# Tables this migration creates. They get the fail-closed policy below; they are
# not in pg_policies until then, so the rewrite list adds them explicitly.
_NEW = ("delivery_outbox", "delivery_cursors")

# Every tenant table that already had tenant_isolation when this was written.
# On Postgres the rewrite also asks pg_policies, so a table added by a migration
# this list missed is still updated. The list is the fallback the coverage test
# hits, because that test replays upgrade() against a mock connection.
_EXISTING = (
    "actor_hours", "agent_roles", "agents", "allow_entries", "api_keys", "audit_log",
    "browser_extensions", "commit_attestations", "containments", "content_fingerprints",
    "corpus_samples", "developer_activity", "device_assets", "discovered_usage",
    "enrollment_tokens", "exception_requests", "exposure_register", "findings",
    "gateway_usage", "inference_hook_denials", "instruction_taints", "join_requests",
    "oauth_codes", "oauth_tokens", "passports", "policy_overrides", "saas_connectors",
    "secret_reach", "secret_rotations", "secret_sightings", "sensor_heartbeats",
    "tenant_domains", "tenant_lanes", "tenant_oidc", "tenant_saml", "tenant_upstreams",
    "tickets", "upgrade_requests", "used_saml_assertions", "users",
)

# Fail closed. A bound tenant sees its rows and NULL-tenant globals. An explicit
# app.cross_tenant='on' sees everything. Anything else sees nothing.
_CLOSED = (
    "current_setting('app.cross_tenant', true) = 'on' "
    "OR ("
    " COALESCE(current_setting('app.tenant_id', true), '') <> '' "
    " AND (tenant_id IS NULL "
    " OR tenant_id::text = current_setting('app.tenant_id', true))"
    ")"
)

# The previous predicate, restored on downgrade. Copied, not imported.
_OPEN = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def _policy_tables(include_new: bool) -> list[str]:
    found: list[str] = []
    try:
        rows = op.get_bind().execute(sa.text(
            "SELECT tablename FROM pg_policies "
            "WHERE schemaname = 'public' AND policyname = 'tenant_isolation'"
        ))
        fetched = rows.fetchall() if hasattr(rows, "fetchall") else list(rows)
        found = [r[0] for r in fetched if r and isinstance(r[0], str)]
    except Exception:
        found = []
    if not found:
        found = list(_EXISTING)
    if include_new:
        for name in _NEW:
            if name not in found:
                found.append(name)
    return found


def _rewrite(predicate: str, tables: list[str]) -> None:
    for t in tables:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def upgrade():
    op.create_table(
        "delivery_outbox",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("sink", sa.String(16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(300), nullable=True),
        sa.Column("claimed_by", sa.String(128), nullable=True),
        sa.Column("claimed_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_delivery_outbox_tenant_id", "delivery_outbox", ["tenant_id"])
    op.create_index("ix_delivery_outbox_next_attempt_at", "delivery_outbox", ["next_attempt_at"])
    op.create_index("ix_delivery_outbox_created_at", "delivery_outbox", ["created_at"])
    op.create_index("ix_delivery_outbox_due", "delivery_outbox", ["status", "next_attempt_at"])

    op.create_table(
        "delivery_cursors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("sink", sa.String(16), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(300), nullable=True),
        sa.Column("dead_count", sa.Integer(), nullable=False),
        sa.UniqueConstraint("tenant_id", "sink", name="uq_delivery_cursor_sink"),
    )
    op.create_index("ix_delivery_cursors_tenant_id", "delivery_cursors", ["tenant_id"])

    op.create_table(
        "cross_tenant_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("reason", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_cross_tenant_audit_reason", "cross_tenant_audit", ["reason"])
    op.create_index("ix_cross_tenant_audit_created_at", "cross_tenant_audit", ["created_at"])

    if op.get_bind().dialect.name != "postgresql":
        return
    for t in _NEW:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
    _rewrite(_CLOSED, _policy_tables(include_new=True))


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        # New tables are about to be dropped; restore the old predicate on the rest.
        tables = [t for t in _policy_tables(include_new=False) if t not in _NEW]
        _rewrite(_OPEN, tables)
    op.drop_index("ix_cross_tenant_audit_created_at", table_name="cross_tenant_audit")
    op.drop_index("ix_cross_tenant_audit_reason", table_name="cross_tenant_audit")
    op.drop_table("cross_tenant_audit")
    op.drop_index("ix_delivery_cursors_tenant_id", table_name="delivery_cursors")
    op.drop_table("delivery_cursors")
    op.drop_index("ix_delivery_outbox_due", table_name="delivery_outbox")
    op.drop_index("ix_delivery_outbox_created_at", table_name="delivery_outbox")
    op.drop_index("ix_delivery_outbox_next_attempt_at", table_name="delivery_outbox")
    op.drop_index("ix_delivery_outbox_tenant_id", table_name="delivery_outbox")
    op.drop_table("delivery_outbox")
