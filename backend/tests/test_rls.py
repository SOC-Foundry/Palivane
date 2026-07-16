"""Database-level Row-Level Security tenant isolation.

RLS only exists on Postgres, and is only *enforced* for a non-superuser role (superusers
and, without FORCE, table owners bypass it). So this test is skipped unless pointed at a
Postgres reachable as a non-superuser via WARDEN_RLS_TEST_URL, e.g.:

    WARDEN_RLS_TEST_URL=postgresql://warden:pw@127.0.0.1:5433/warden \\
        pytest tests/test_rls.py

It assumes migrations (incl. a9f1c3e5b7d0) have been applied to that database. All rows it
creates are rolled back.
"""
import os

import pytest

psycopg2 = pytest.importorskip("psycopg2")

URL = os.getenv("WARDEN_RLS_TEST_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set WARDEN_RLS_TEST_URL to a non-superuser Postgres")


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
