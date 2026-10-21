"""Row-Level Security on the tenant tables a9f1c3e5b7d0 and its follow-ups missed

Revision ID: f758200a1b4b
Revises: d9b6a24e8c71
Create Date: 2026-10-20

Seven tables carry a tenant_id but were added (or overlooked) after the original RLS
migration, so the database-level isolation /trust describes did not cover them:
connector credentials, OAuth codes/tokens, content fingerprints, the ML capture corpus,
upgrade requests and the SAML replay ledger. Same policy as a9f1c3e5b7d0, verbatim.

Pre-auth lookups keep working with no bypass function, because the predicate falls open
when `app.tenant_id` is unset — which is exactly the state of every code path that runs
before database.bind_tenant():
  * OAuth token lookup by token hash (mcp_remote) and the /token code exchange,
  * the SAML ACS replay check and its expired-row sweep,
  * Slack/GitHub webhook routing (find the connector, THEN bind its tenant),
  * the connector scheduler's cross-tenant due-list and claim (it binds per connector and
    every path through a sync commits before clear_tenant, so the next claim starts a fresh,
    unbound transaction),
  * the operator-token /api/admin/upgrade-requests queue (never binds a tenant),
  * the retention purge of unlabeled corpus samples (background, unbound).
Inside a bound request each of these tables is only ever queried for that request's own
tenant, so RLS removes nothing the code was relying on.

oauth_codes, oauth_tokens and used_saml_assertions have a nullable tenant_id; NULL rows
stay visible to every tenant, as with findings.

tests/test_rls_coverage.py fails if a model gains a tenant_id without being listed in one
of the RLS migrations, so the next table cannot be forgotten the same way.

No-op on SQLite.
"""
from alembic import op

revision = "f758200a1b4b"
down_revision = "d9b6a24e8c71"
branch_labels = None
depends_on = None

TABLES = [
    "saas_connectors", "oauth_tokens", "oauth_codes", "content_fingerprints",
    "corpus_samples", "upgrade_requests", "used_saml_assertions",
]

# Identical to a9f1c3e5b7d0._PREDICATE (copied, not imported: migrations must not change
# behaviour if an earlier file is edited).
_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
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
