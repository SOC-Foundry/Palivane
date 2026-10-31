"""OAuth tables: the indexes the models always declared

models.py has marked these columns index=True since the OAuth tables landed, but
e5a71c0b93df only created the token/code hash and expires_at indexes. SQLite (create_all)
had them; Postgres never did, so refresh-token lookup by client, revoke-all-for-user on a
password change, the idle-client sweep's NOT EXISTS probes, and the RLS tenant_id predicate
all scanned the whole table.

Additive. IF NOT EXISTS in case an operator added any by hand.

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


def upgrade() -> None:
    for table, col in INDEXES:
        op.create_index(f"ix_{table}_{col}", table, [col], if_not_exists=True)


def downgrade() -> None:
    for table, col in INDEXES:
        op.drop_index(f"ix_{table}_{col}", table_name=table, if_exists=True)
