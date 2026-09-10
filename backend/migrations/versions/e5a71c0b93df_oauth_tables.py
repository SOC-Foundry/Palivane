"""oauth_clients / oauth_codes / oauth_tokens — authorization server for remote MCP

Palivane is its own authorization server because it is its own identity provider: users,
roles and tenants live here and there is no external IdP every tenant shares. The MCP SDK
supplies the protocol; these tables supply persistence and, in oauth_codes.user_id, the
consent binding that decides whose data a token may read.

Three deliberate shapes:

  - Credentials are stored HASHED (code_hash, token_hash, client_secret_hash), never in the
    clear, matching how api_keys already works. A database read must not yield a usable
    credential.
  - redirect_uris is an exact-match allowlist, newline-separated. Never prefix-matched: a
    loose redirect check is how authorization codes get delivered to somebody else.
  - oauth_codes carries used_at and a short expires_at, because a code that can be replayed
    is a code that can be stolen from a log or a referrer header and used twice.

Additive and unreachable: no routes are wired to these yet. Storage lands first so the token
mechanics can be reviewed before a browser can reach any of it.

Revision ID: e5a71c0b93df
Revises: d3e81b90fa27
"""

import sqlalchemy as sa
from alembic import op

revision = "e5a71c0b93df"
down_revision = "d3e81b90fa27"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("client_id", sa.String(64), nullable=False, unique=True),
        sa.Column("client_secret_hash", sa.String(64), server_default=""),
        sa.Column("client_name", sa.String(200), server_default=""),
        sa.Column("redirect_uris", sa.Text(), server_default=""),
        sa.Column("scope", sa.String(200), server_default=""),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index("ix_oauth_clients_client_id", "oauth_clients", ["client_id"], unique=True)

    op.create_table(
        "oauth_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("redirect_uri", sa.Text(), server_default=""),
        sa.Column("code_challenge", sa.String(128), server_default=""),
        sa.Column("scopes", sa.String(200), server_default=""),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index("ix_oauth_codes_code_hash", "oauth_codes", ["code_hash"], unique=True)
    op.create_index("ix_oauth_codes_expires_at", "oauth_codes", ["expires_at"])

    op.create_table(
        "oauth_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("kind", sa.String(8), server_default="access"),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("scopes", sa.String(200), server_default=""),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index("ix_oauth_tokens_token_hash", "oauth_tokens", ["token_hash"], unique=True)
    op.create_index("ix_oauth_tokens_expires_at", "oauth_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("oauth_tokens")
    op.drop_table("oauth_codes")
    op.drop_table("oauth_clients")
