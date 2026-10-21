"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}

# Checklist (delete once read):
# * revision id: random (python -c "import secrets;print(secrets.token_hex(6))"), never
#   hand-typed — ids have collided before. After adding, `alembic heads` must show ONE head.
# * A new table with tenant_id needs the tenant_isolation RLS policy in the same migration
#   (see f758200a1b4b); tests/test_rls_coverage.py fails until it has one.
# * New indexes on large/hot tables (findings, audit_log, gateway_usage, ...) must not take
#   a write lock for the whole build in production:
#       with op.get_context().autocommit_block():
#           op.create_index("ix_...", "findings", ["col"], postgresql_concurrently=True,
#                           if_not_exists=True)
#   (and the same with drop_index in downgrade). CONCURRENTLY cannot run inside a
#   transaction, hence the autocommit block; it is ignored on SQLite.


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
