"""SQLAlchemy engine/session setup.

Tenant isolation is enforced in two layers: application-level `tenant_id` filters on
every query, and — on Postgres — database-level Row-Level Security (see the
`*_rls_tenant_isolation` migration). RLS keys off a per-transaction GUC `app.tenant_id`:
when it is set, a connection can only see/write rows for that tenant (plus `NULL`-tenant
"global" rows); when it is unset (system/background/auth paths that legitimately span
tenants) the policies fall open. `bind_tenant()` sets it for an authenticated request; the
`after_begin` listener re-applies it across any mid-request commits.

The tenant lives on the Session (`Session.info`), not in a ContextVar: FastAPI runs sync
dependencies in a worker thread with a copied context, so a ContextVar set during auth
was invisible to the endpoint and every transaction after the first commit fell open.
"""

from __future__ import annotations

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .config import settings

if settings.database_url.startswith("sqlite"):
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
else:
    # Each process holds up to pool_size + max_overflow connections, and every instance is a
    # process, so instances x that must stay under the server's connection ceiling (25 on
    # Cloud SQL db-f1-micro). pre_ping swaps out a connection the server dropped while it
    # sat idle instead of failing the request that drew it.
    engine = create_engine(settings.database_url, pool_size=settings.db_pool_size,
                           max_overflow=settings.db_max_overflow, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

_IS_PG = engine.dialect.name == "postgresql"

# Session.info key holding the session's tenant; absent/None for system/cross-tenant
# contexts (RLS falls open).
_TENANT_KEY = "palivane_tenant_id"


def _apply_tenant(connection, tenant_id: int | None) -> None:
    # local=true -> scoped to the current transaction; auto-clears on commit/rollback so a
    # pooled connection never leaks one request's tenant into the next.
    val = "" if tenant_id is None else str(tenant_id)
    connection.exec_driver_sql("SELECT set_config('app.tenant_id', %s, true)", (val,))


def bound_tenant(db: Session) -> int | None:
    return db.info.get(_TENANT_KEY)


def bind_tenant(db: Session, tenant_id: int | None) -> None:
    """Scope this session to `tenant_id` for the rest of its life (RLS enforced), across
    commits, until rebound or cleared."""
    db.info[_TENANT_KEY] = int(tenant_id) if tenant_id is not None else None
    if _IS_PG:
        db.execute(text("SELECT set_config('app.tenant_id', :t, true)"),
                   {"t": "" if tenant_id is None else str(tenant_id)})


def clear_tenant(db: Session) -> None:
    """Back to system scope, for a session that goes on to cross-tenant work."""
    db.info.pop(_TENANT_KEY, None)
    if _IS_PG and db.in_transaction():
        db.execute(text("SELECT set_config('app.tenant_id', '', true)"))


def _reapply_tenant(session, transaction, connection):  # noqa: ANN001
    # Re-assert the tenant GUC whenever a new transaction begins (e.g. after a
    # mid-request commit), from the session's own binding.
    _apply_tenant(connection, session.info.get(_TENANT_KEY))


if _IS_PG:
    event.listen(SessionLocal, "after_begin", _reapply_tenant)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
