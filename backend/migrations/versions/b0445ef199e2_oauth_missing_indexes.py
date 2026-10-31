"""OAuth tables: the indexes the models always declared

models.py has marked these columns index=True since the OAuth tables landed, but
e5a71c0b93df only created the token/code hash and expires_at indexes. SQLite (create_all)
had them; Postgres never did, so refresh-token lookup by client, revoke-all-for-user on a
password change, the idle-client sweep's NOT EXISTS probes, and the RLS tenant_id predicate
all scanned the whole table.

Additive. IF NOT EXISTS in case an operator added any by hand.

Also drops three duplicate uniqueness checks on Postgres. e5a71c0b93df declared
client_id / code_hash / token_hash both `unique=True` on the column (a `<table>_<col>_key`
constraint) and as a unique ix_ index, so every insert maintained two identical btrees. The
ix_ unique indexes stay and keep enforcing uniqueness; they are what the models declare.
SQLite never got the duplicate (and cannot drop a constraint in place), so it is skipped.

Revision ID: b0445ef199e2
Revises: 098f19800b66
"""

from alembic import op

revision = "b0445ef199e2"
down_revision = "098f19800b66"
branch_labels = None
depends_on = None

INDEXES = [
    ("oauth_clients", "created_at"),
    ("oauth_codes", "client_id"),
    ("oauth_codes", "user_id"),
    ("oauth_codes", "tenant_id"),
    ("oauth_tokens", "client_id"),
    ("oauth_tokens", "user_id"),
    ("oauth_tokens", "tenant_id"),
    ("oauth_tokens", "created_at"),
]

# Duplicated by the unique ix_ index on the same column.
DUP_UNIQUE = [
    ("oauth_clients", "client_id"),
    ("oauth_codes", "code_hash"),
    ("oauth_tokens", "token_hash"),
]


def upgrade() -> None:
    for table, col in INDEXES:
        op.create_index(f"ix_{table}_{col}", table, [col], if_not_exists=True)
    if op.get_bind().dialect.name == "postgresql":
        for table, col in DUP_UNIQUE:
            op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {table}_{col}_key")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table, col in DUP_UNIQUE:
            op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {table}_{col}_key UNIQUE ({col})")
    for table, col in INDEXES:
        op.drop_index(f"ix_{table}_{col}", table_name=table, if_exists=True)
