"""SQLAlchemy engine/session setup.

Tenant isolation is enforced in two layers: application-level `tenant_id` filters on
every query, and — on Postgres — database-level Row-Level Security. RLS keys off two
per-transaction GUCs:

* `app.tenant_id` — set by `bind_tenant` for an authenticated request. The session can
  see and write that tenant's rows, plus `NULL`-tenant global rows.
* `app.cross_tenant` — set to `on` only by `allow_cross_tenant`, the explicit opt-in
  for login lookups and cross-tenant jobs. The call records why.

When neither is set the policies fail closed: a request that forgot to bind sees no
tenant rows and cannot write them. That used to fall open, so a missing bind returned
every tenant's data.

The tenant lives on the Session (`Session.info`), not in a ContextVar: FastAPI runs sync
dependencies in a worker thread with a copied context, so a ContextVar set during auth
was invisible to the endpoint and every transaction after the first commit fell open.
The `after_begin` listener re-applies whichever scope the session holds.

Request-scoped sessions (the ones `get_db` yields) also refuse, in the application, to
run a tenant-table statement until they are bound or explicitly cross-tenant. That
check runs on SQLite too, where RLS does not, so the ordinary test suite catches a
handler that queries before it binds.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.sql import visitors

from .config import settings

log = logging.getLogger("uvicorn.error")

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

# Session.info keys. Absent tenant + absent cross-tenant reason = fail closed.
_TENANT_KEY = "palivane_tenant_id"
_CROSS_KEY = "palivane_cross_tenant"       # the reason string, when the bypass is on
_REQUEST_KEY = "palivane_request_scoped"

# Reasons written on every call (login, operator, domain capture). Credential lookups
# and background ticks are recorded once per process: they run on every request or every
# couple of seconds, and a row each time would be the table. The log line still fires
# the first time; later ones are debug.
_AUDIT_ONCE_PREFIXES = ("auth.api_key", "auth.agent", "auth.oauth", "auth.session",
                        "job.", "webhook.")
_audited_once: set[str] = set()


class TenantScopeError(RuntimeError):
    """A request-scoped session touched a tenant table with no tenant and no bypass."""


def _apply_tenant(connection, tenant_id: int | None) -> None:
    # local=true -> scoped to the current transaction; auto-clears on commit/rollback so a
    # pooled connection never leaks one request's tenant into the next.
    if not _IS_PG:
        return
    val = "" if tenant_id is None else str(tenant_id)
    connection.exec_driver_sql("SELECT set_config('app.tenant_id', %s, true)", (val,))


def _apply_cross(connection, enabled: bool) -> None:
    if not _IS_PG:
        return
    connection.exec_driver_sql(
        "SELECT set_config('app.cross_tenant', %s, true)", ("on" if enabled else "",))


def _apply_now(db: Session) -> None:
    """Push the session's current scope into the open transaction's GUCs."""
    if not _IS_PG:
        return
    cross = bool(db.info.get(_CROSS_KEY))
    tid = None if cross else db.info.get(_TENANT_KEY)
    db.execute(text(
        "SELECT set_config('app.tenant_id', :t, true), set_config('app.cross_tenant', :c, true)"
    ), {"t": "" if tid is None else str(tid), "c": "on" if cross else ""})


def bound_tenant(db: Session) -> int | None:
    if db.info.get(_CROSS_KEY):
        return None
    return db.info.get(_TENANT_KEY)


def bind_tenant(db: Session, tenant_id: int | None) -> None:
    """Scope this session to `tenant_id` for the rest of its life (RLS enforced), across
    commits, until rebound or cleared. Clears any cross-tenant bypass: binding is how a
    login lookup that had to see every org narrows back down to the one that signed in.

    `bind_tenant(db, None)` fails closed. It does not restore the old fall-open behavior.
    """
    db.info.pop(_CROSS_KEY, None)
    if tenant_id is None:
        db.info.pop(_TENANT_KEY, None)
    else:
        db.info[_TENANT_KEY] = int(tenant_id)
    _apply_now(db)


def clear_tenant(db: Session) -> None:
    """Fail closed: drop both the tenant bind and any cross-tenant bypass."""
    db.info.pop(_TENANT_KEY, None)
    db.info.pop(_CROSS_KEY, None)
    if _IS_PG and db.in_transaction():
        _apply_now(db)


def _persist_audit(db: Session, reason: str) -> None:
    once = reason.startswith(_AUDIT_ONCE_PREFIXES)
    if once and reason in _audited_once:
        log.debug("cross-tenant scope: %s", reason)
        return
    _audited_once.add(reason)
    log.info("cross-tenant scope enabled: %s", reason)
    try:
        from .models import CrossTenantAudit
        db.add(CrossTenantAudit(reason=reason[:120]))
    except Exception:
        log.warning("cross-tenant audit row failed for %s", reason, exc_info=True)


def allow_cross_tenant(db: Session, reason: str) -> None:
    """Opt this session into seeing every tenant until `bind_tenant` or `clear_tenant`.

    `reason` is required and recorded (an audit row, and a log line). This is the only
    supported way to do work that legitimately spans tenants: login before the org is
    known, webhook routing, the operator console, and the background loops. A request
    that merely forgot to bind does not get here, and on Postgres it sees nothing.
    """
    reason = " ".join((reason or "").split())[:120]
    if not reason:
        raise ValueError("cross-tenant access requires a reason")
    db.info[_CROSS_KEY] = reason
    db.info.pop(_TENANT_KEY, None)
    _persist_audit(db, reason)
    _apply_now(db)


def ensure_cross_tenant(db: Session, reason: str) -> None:
    """Open a cross-tenant scope only when the session is not already bound.

    Shared helpers run both before auth (they must see every tenant to find the row)
    and after (they must not widen a request that is already scoped). A session that
    is already cross-tenant is left on its existing reason.
    """
    if db.info.get(_TENANT_KEY) is not None and not db.info.get(_CROSS_KEY):
        return
    if db.info.get(_CROSS_KEY):
        return
    allow_cross_tenant(db, reason)


def mark_request(db: Session) -> None:
    """This session belongs to one HTTP request. Tenant-table SQL before a bind raises."""
    db.info[_REQUEST_KEY] = True


def _reapply_tenant(session, transaction, connection):  # noqa: ANN001
    # Re-assert scope whenever a new transaction begins (e.g. after a mid-request
    # commit), from the session's own binding. Cross-tenant wins over a stale tenant id.
    cross = bool(session.info.get(_CROSS_KEY))
    tid = None if cross else session.info.get(_TENANT_KEY)
    _apply_tenant(connection, tid)
    _apply_cross(connection, cross)


if _IS_PG:
    event.listen(SessionLocal, "after_begin", _reapply_tenant)


_tenant_tables: frozenset[str] | None = None


def tenant_table_names() -> frozenset[str]:
    """Tables that carry a tenant_id column. Empty until the models are imported."""
    global _tenant_tables
    names = frozenset(
        table.name for table in Base.metadata.tables.values() if "tenant_id" in table.c)
    if names:
        _tenant_tables = names
    return _tenant_tables or frozenset()


def _statement_touches_tenant(statement) -> bool:
    known = tenant_table_names()
    if not known:
        return False
    found: set[str] = set()
    try:
        for el in visitors.iterate(statement):
            name = getattr(el, "name", None)
            if isinstance(name, str) and el.__class__.__name__ == "Table":
                found.add(name)
    except Exception:
        found = set()
    if found & known:
        return True
    try:
        sql = str(statement.compile(compile_kwargs={"literal_binds": False}))
    except Exception:
        sql = str(statement)
    return any(re.search(rf"\b{re.escape(name)}\b", sql, re.I) for name in known)


@event.listens_for(Session, "do_orm_execute")
def _guard_request_scope(state):  # noqa: ANN001
    session = state.session
    if not session.info.get(_REQUEST_KEY):
        return
    if session.info.get(_CROSS_KEY) or session.info.get(_TENANT_KEY) is not None:
        return
    if _statement_touches_tenant(state.statement):
        try:
            sql = " ".join(str(state.statement).split())[:240]
        except Exception:
            sql = ""
        raise TenantScopeError(
            "request-scoped session queried a tenant table without bind_tenant "
            f"or allow_cross_tenant: {sql}")


def get_db():
    db = SessionLocal()
    mark_request(db)
    try:
        yield db
    finally:
        db.close()
