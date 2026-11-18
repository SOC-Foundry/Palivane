"""Postgres: an unset app.tenant_id fails closed, and the app's opt-in is what opens it.

Runs in the rls CI job (PALIVANE_RLS_TEST_URL, non-superuser). Skips elsewhere.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app import database
from app.config import pin_postgres_driver

psycopg2 = pytest.importorskip("psycopg2")

URL = os.environ.get("PALIVANE_RLS_TEST_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set PALIVANE_RLS_TEST_URL to a non-superuser Postgres")


def _guc(db, name: str) -> str:
    return db.execute(text(f"SELECT current_setting('{name}', true)")).scalar() or ""


def test_live_policies_require_a_tenant_or_an_explicit_bypass():
    conn = psycopg2.connect(URL)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT tablename, qual, with_check
            FROM pg_policies
            WHERE schemaname = 'public' AND policyname = 'tenant_isolation'""")
        rows = cur.fetchall()
        assert rows, "no tenant_isolation policies — migrations not applied?"
        names = {r[0] for r in rows}
        assert {"findings", "users", "delivery_outbox", "delivery_cursors"} <= names
        for name, qual, check in rows:
            blob = f"{qual or ''} {check or ''}"
            assert "app.cross_tenant" in blob, name
            assert "current_setting('app.tenant_id', true) IS NULL" not in blob, name
            assert "current_setting('app.tenant_id', true) = ''" not in blob, name
    finally:
        conn.close()


def test_unset_context_hides_rows_bypass_and_bind_reveal_them():
    conn = psycopg2.connect(URL)
    try:
        cur = conn.cursor()
        cur.execute("SELECT set_config('app.cross_tenant', 'on', true)")
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-fc-a', 'A') RETURNING id")
        a = cur.fetchone()[0]
        cur.execute("INSERT INTO tenants (slug, name) VALUES ('rls-fc-b', 'B') RETURNING id")
        b = cur.fetchone()[0]
        cur.execute("INSERT INTO findings (tenant_id) VALUES (%s)", (a,))
        cur.execute("INSERT INTO findings (tenant_id) VALUES (%s)", (b,))
        cur.execute("INSERT INTO findings (tenant_id) VALUES (NULL)")

        cur.execute("SELECT set_config('app.cross_tenant', '', true)")
        cur.execute("SELECT set_config('app.tenant_id', '', true)")
        cur.execute("SELECT count(*) FROM findings")
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT set_config('app.tenant_id', %s, true)", (str(a),))
        cur.execute("SELECT count(*) FROM findings")
        assert cur.fetchone()[0] == 2          # A's row + the NULL global
        cur.execute("SELECT count(*) FROM findings WHERE tenant_id = %s", (b,))
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT set_config('app.tenant_id', '', true)")
        cur.execute("SELECT set_config('app.cross_tenant', 'on', true)")
        cur.execute("SELECT count(*) FROM findings WHERE tenant_id IN (%s, %s) OR tenant_id IS NULL",
                    (a, b))
        assert cur.fetchone()[0] == 3
    finally:
        conn.rollback()
        conn.close()


def test_sqlalchemy_opt_in_sets_the_guc_and_bind_clears_it(monkeypatch):
    monkeypatch.setattr(database, "_IS_PG", True)
    engine = create_engine(pin_postgres_driver(URL))
    maker = sessionmaker(bind=engine)
    event.listen(maker, "after_begin", database._reapply_tenant)
    db = maker()
    try:
        database.allow_cross_tenant(db, "test.job")
        assert _guc(db, "app.cross_tenant") == "on"
        assert _guc(db, "app.tenant_id") == ""
        db.commit()
        assert _guc(db, "app.cross_tenant") == "on"     # re-applied on the next transaction
        database.bind_tenant(db, 7)
        assert _guc(db, "app.tenant_id") == "7"
        assert _guc(db, "app.cross_tenant") == ""
        db.commit()
        assert _guc(db, "app.tenant_id") == "7"
        database.clear_tenant(db)
        assert _guc(db, "app.tenant_id") == ""
        assert _guc(db, "app.cross_tenant") == ""
        db.commit()
        assert _guc(db, "app.tenant_id") == ""
        assert _guc(db, "app.cross_tenant") == ""
    finally:
        db.close()
        engine.dispose()
