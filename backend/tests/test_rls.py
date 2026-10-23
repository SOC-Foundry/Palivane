"""Database-level Row-Level Security tenant isolation.

RLS only exists on Postgres, and is only *enforced* for a non-superuser role (superusers
and, without FORCE, table owners bypass it). So this test is skipped unless pointed at a
Postgres reachable as a non-superuser via PALIVANE_RLS_TEST_URL, e.g.:

    PALIVANE_RLS_TEST_URL=postgresql://palivane:pw@127.0.0.1:5433/palivane \\
        pytest tests/test_rls.py

It assumes migrations (incl. a9f1c3e5b7d0) have been applied to that database. All rows it
creates are rolled back.
"""
import os

import pytest

psycopg2 = pytest.importorskip("psycopg2")

URL = os.getenv("PALIVANE_RLS_TEST_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set PALIVANE_RLS_TEST_URL to a non-superuser Postgres")


def _scope(cur, val):
    cur.execute("SELECT set_config('app.tenant_id', %s, true)", (val,))


def test_rls_read_and_write_isolation():
    conn = psycopg2.connect(URL)
    try:
        cur = conn.cursor()
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        assert cur.fetchone()[0] is False, "RLS is not enforced for superusers — use a plain role"

        # Seed with no tenant context (policies fall open).
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-a', 'A') RETURNING id")
        a = cur.fetchone()[0]
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-b', 'B') RETURNING id")
        b = cur.fetchone()[0]
        cur.execute("INSERT INTO findings (tenant_id) VALUES (%s)", (a,))
        cur.execute("INSERT INTO findings (tenant_id) VALUES (%s)", (b,))
        cur.execute("INSERT INTO findings (tenant_id) VALUES (NULL)")  # global/shared

        # Scoped to A: sees only A's rows plus NULL-tenant globals.
        _scope(cur, str(a))
        cur.execute("SELECT count(*) FROM findings")
        assert cur.fetchone()[0] == 2
        # ...and cannot reach B's rows even asking for them explicitly.
        cur.execute("SELECT count(*) FROM findings WHERE tenant_id = %s", (b,))
        assert cur.fetchone()[0] == 0

        # WITH CHECK: cannot write a row belonging to another tenant. Wrap in a savepoint
        # so the aborted statement doesn't roll back the seed data with it.
        cur.execute("SAVEPOINT sp")
        with pytest.raises(psycopg2.Error):
            cur.execute("INSERT INTO findings (tenant_id) VALUES (%s)", (b,))
        cur.execute("ROLLBACK TO SAVEPOINT sp")
        # ...but can write its own.
        cur.execute("INSERT INTO findings (tenant_id) VALUES (%s)", (a,))

        # Back to no context: everything is visible again.
        _scope(cur, "")
        cur.execute("SELECT count(*) FROM tenants WHERE slug IN ('rls-a', 'rls-b')")
        assert cur.fetchone()[0] == 2
    finally:
        conn.rollback()
        conn.close()


def test_owner_match_on_postgres_stays_in_tenant():
    """The /api/my/findings document-owner match (`origin ->> 'owner'` on a json column) runs
    on real Postgres, and RLS alone keeps it inside the scoped tenant: the same owner address
    on a finding in another tenant is invisible even without the app's tenant_id filter."""
    from sqlalchemy import select
    from sqlalchemy.dialects import postgresql

    from app.main import _owner_match
    from app.models import Finding
    sql = str(select(Finding.id).where(_owner_match("owner@rls.test"))
              .compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    conn = psycopg2.connect(URL)
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-e', 'E') RETURNING id")
        a = cur.fetchone()[0]
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-f', 'F') RETURNING id")
        b = cur.fetchone()[0]
        ids = {}
        for t in (a, b):
            cur.execute("INSERT INTO findings (tenant_id, origin) VALUES (%s, %s::json) "
                        "RETURNING id", (t, '{"owner": "Owner@RLS.test", "title": "doc"}'))
            ids[t] = cur.fetchone()[0]
        cur.execute("INSERT INTO findings (tenant_id, origin) VALUES (%s, NULL)", (a,))

        _scope(cur, str(a))
        cur.execute(sql)
        assert [r[0] for r in cur.fetchall()] == [ids[a]]
        _scope(cur, str(b))
        cur.execute(sql)
        assert [r[0] for r in cur.fetchall()] == [ids[b]]
    finally:
        conn.rollback()
        conn.close()


def test_every_tenant_table_has_forced_rls_and_policy():
    """Catalog check against the REAL migrated schema: every table with a tenant_id column
    has RLS enabled AND forced (the app connects as the owner) and a tenant_isolation
    policy. test_rls_coverage.py checks the same against the migration sources without a
    database; this one catches a migration that ran differently than its source suggests."""
    conn = psycopg2.connect(URL)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                   EXISTS (SELECT 1 FROM pg_policies p
                           WHERE p.schemaname = 'public' AND p.tablename = c.relname
                             AND p.policyname = 'tenant_isolation')
            FROM information_schema.columns col
            JOIN pg_class c ON c.relname = col.table_name
            JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
            WHERE col.table_schema = 'public' AND col.column_name = 'tenant_id'
              AND c.relkind = 'r'""")
        rows = cur.fetchall()
        assert rows, "no tenant_id tables found — migrations not applied?"
        bad = sorted(r[0] for r in rows if not (r[1] and r[2] and r[3]))
        assert not bad, f"tenant tables without enabled+forced RLS and a policy: {bad}"
        # The seven f758200a1b4b covers must be among them (guards against a vacuous pass).
        names = {r[0] for r in rows}
        assert {"saas_connectors", "oauth_tokens", "oauth_codes", "content_fingerprints",
                "corpus_samples", "upgrade_requests", "used_saml_assertions"} <= names
    finally:
        conn.close()


def test_rls_isolation_on_tables_added_by_f758200a1b4b():
    """Behavioural check on two of the newly covered tables: one with a NOT NULL tenant_id
    (upgrade_requests) and one nullable (used_saml_assertions — the SAML replay ledger,
    written pre-auth with no tenant bound, which must keep working)."""
    conn = psycopg2.connect(URL)
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-c', 'C') RETURNING id")
        a = cur.fetchone()[0]
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-d', 'D') RETURNING id")
        b = cur.fetchone()[0]
        for t in (a, b):
            cur.execute("INSERT INTO upgrade_requests (tenant_id, plan, status) "
                        "VALUES (%s, 'team', 'pending')", (t,))
        # Unbound, as on the SAML ACS path: the insert works for any tenant.
        cur.execute("INSERT INTO used_saml_assertions (tenant_id, assertion_id) "
                    "VALUES (%s, 'rls-x')", (b,))

        _scope(cur, str(a))
        cur.execute("SELECT count(*) FROM upgrade_requests WHERE tenant_id IN (%s, %s)", (a, b))
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM used_saml_assertions WHERE assertion_id = 'rls-x'")
        assert cur.fetchone()[0] == 0
        cur.execute("SAVEPOINT sp")
        with pytest.raises(psycopg2.Error):
            cur.execute("INSERT INTO upgrade_requests (tenant_id, plan, status) "
                        "VALUES (%s, 'team', 'pending')", (b,))
        cur.execute("ROLLBACK TO SAVEPOINT sp")

        _scope(cur, "")
        cur.execute("SELECT count(*) FROM upgrade_requests WHERE tenant_id IN (%s, %s)", (a, b))
        assert cur.fetchone()[0] == 2
    finally:
        conn.rollback()
        conn.close()
