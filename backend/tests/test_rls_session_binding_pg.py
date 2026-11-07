"""On real Postgres: a session bound to a tenant keeps app.tenant_id set in every
transaction, including the ones after a commit, until it is cleared. Before the binding
moved onto the Session, the GUC was empty after the first commit and RLS fell open.
Runs in CI's RLS job (PALIVANE_RLS_TEST_URL); skips elsewhere."""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app import database

URL = os.environ.get("PALIVANE_RLS_TEST_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set PALIVANE_RLS_TEST_URL to a Postgres")


def _guc(db) -> str:
    return db.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar() or ""


def test_tenant_guc_survives_commits_until_cleared(monkeypatch):
    monkeypatch.setattr(database, "_IS_PG", True)     # the app's own DB may be sqlite here
    from app.config import pin_postgres_driver
    engine = create_engine(pin_postgres_driver(URL))
    maker = sessionmaker(bind=engine)
    event.listen(maker, "after_begin", database._reapply_tenant)
    db = maker()
    try:
        database.bind_tenant(db, 7)
        assert _guc(db) == "7"
        for _ in range(2):
            db.commit()
            assert _guc(db) == "7"          # a fresh transaction, still scoped
        database.clear_tenant(db)
        assert _guc(db) == ""
        db.commit()
        assert _guc(db) == ""
    finally:
        db.close()
        engine.dispose()
