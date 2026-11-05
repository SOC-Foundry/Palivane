"""The RLS tenant binding belongs to the Session, so it survives what a ContextVar did not:
being set in a sync dependency's worker thread, and mid-request commits. Each new
transaction re-applies it (the Postgres after_begin hook, exercised here on sqlite)."""
from __future__ import annotations

import contextvars
import threading

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app import database


def _session_with_hook(monkeypatch):
    applied = []
    monkeypatch.setattr(database, "_apply_tenant", lambda conn, tid: applied.append(tid))
    maker = sessionmaker(bind=create_engine("sqlite://"))
    event.listen(maker, "after_begin", database._reapply_tenant)
    return maker(), applied


def test_binding_set_in_a_worker_thread_is_seen_by_the_endpoint():
    db = sessionmaker(bind=create_engine("sqlite://"))()
    ctx = contextvars.copy_context()           # what run_in_threadpool does for a sync dependency
    t = threading.Thread(target=ctx.run, args=(database.bind_tenant, db, 7))
    t.start(); t.join()
    assert database.bound_tenant(db) == 7


def test_every_transaction_after_a_commit_is_still_bound(monkeypatch):
    db, applied = _session_with_hook(monkeypatch)
    database.bind_tenant(db, 7)
    for _ in range(3):
        db.execute(text("SELECT 1"))
        db.commit()
    assert applied == [7, 7, 7]


def test_clear_returns_the_session_to_system_scope(monkeypatch):
    db, applied = _session_with_hook(monkeypatch)
    database.bind_tenant(db, 7)
    database.clear_tenant(db)
    db.execute(text("SELECT 1"))
    assert database.bound_tenant(db) is None and applied == [None]


def test_sessions_do_not_share_a_binding():
    maker = sessionmaker(bind=create_engine("sqlite://"))
    a, b = maker(), maker()
    database.bind_tenant(a, 7)
    assert database.bound_tenant(b) is None


def test_ingest_auth_binds_the_callers_tenant(monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "_ingest_caller_unbound", lambda tok, db: (5, "dev", False))
    db = sessionmaker(bind=create_engine("sqlite://"))()
    assert m._ingest_auth("x", db) == (5, "dev")
    assert database.bound_tenant(db) == 5
