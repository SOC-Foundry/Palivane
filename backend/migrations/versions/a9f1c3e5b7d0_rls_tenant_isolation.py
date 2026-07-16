"""Row-Level Security tenant isolation (Postgres only)

Revision ID: a9f1c3e5b7d0
Revises: f8b0d2c4e6a9
Create Date: 2026-07-16

Database-enforced tenant isolation as defense-in-depth over the app-level tenant_id
filters. Each protected table gets a policy keyed on the per-transaction GUC
`app.tenant_id` (set by database.bind_tenant for authenticated requests):

  visible/writable  <=>  app.tenant_id unset   (system/background/auth: falls open)
                    OR   tenant_id IS NULL      (global/shared rows stay visible to all)
                    OR   tenant_id = app.tenant_id

FORCE is required because the app connects as the table owner, who would otherwise
bypass RLS. No-op on SQLite (self-host / tests), which has no RLS.
"""
from alembic import op

revision = "a9f1c3e5b7d0"
down_revision = "f8b0d2c4e6a9"
branch_labels = None
depends_on = None

# Tenant-scoped tables. All carry a `tenant_id` column; the policy handles the nullable
# ones (policy_overrides, discovered_usage, findings) via the `tenant_id IS NULL` clause.
TABLES = [
    "users", "api_keys", "enrollment_tokens", "tenant_domains", "join_requests",
    "tenant_upstreams", "audit_log", "gateway_usage", "tenant_oidc", "tenant_saml",
    "findings", "discovered_usage", "agents", "agent_roles", "policy_overrides",
]

_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    # compare column-as-text (never casts the possibly-empty GUC to int, which would
    # throw since SQL does not guarantee OR short-circuit evaluation)
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
        )


def downgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
