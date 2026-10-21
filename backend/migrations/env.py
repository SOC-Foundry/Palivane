"""Alembic environment — wired to the app's settings and ORM metadata."""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, text

from alembic import context

from app import models  # noqa: F401 — registers all tables on Base.metadata
from app.config import settings
from app.database import Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

# Always migrate the database the app is configured to use.
config.set_main_option("sqlalchemy.url", settings.database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# Serialises concurrent `alembic upgrade head` runs. docker-entrypoint.sh migrates in every
# container at start, and Cloud Run starts several instances at once (min-instances >= 2,
# plus scale-out during a rollout), so without this two containers can both see revision N
# and both try to apply N+1 — one dies on "relation already exists" mid-migration. A
# session-level advisory lock makes the others wait; when they get it, alembic re-reads
# alembic_version under the lock and finds nothing left to do. Arbitrary constant, unique
# to this purpose ("palivane" as ASCII, fits a signed bigint).
_MIGRATION_LOCK_KEY = 0x70616C6976616E65 & 0x7FFFFFFFFFFFFFFF


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        is_pg = connection.dialect.name == "postgresql"
        if is_pg:
            # Session-level (not xact) lock: it must outlive the per-migration commits and any
            # autocommit_block() a migration opens. Blocks until the holder finishes.
            connection.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _MIGRATION_LOCK_KEY})
            # SQLAlchemy 2.x autobegan a transaction for that SELECT; end it so alembic
            # starts (and commits) its own instead of nesting inside one nobody commits.
            connection.commit()
        try:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,
            )
            with context.begin_transaction():
                context.run_migrations()
        finally:
            if is_pg:
                # Closing the connection would release it too; explicit so a failed run never
                # leaves the next container waiting on a connection that lingers.
                if connection.in_transaction():
                    connection.rollback()
                connection.execute(text("SELECT pg_advisory_unlock(:k)"),
                                   {"k": _MIGRATION_LOCK_KEY})
                connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
