"""api_keys.scope + user_id — console-capable API keys, existing keys grandfathered

An api_key used to mean exactly one thing: an ingest credential for the gateway and SIEM
planes. The console API (get_current_user) refused them outright. Making that same
credential work against the console — so the MCP server has a long-lived alternative to a
12h session JWT — would have silently promoted every key already issued in the field into
one that can read findings, change policy, and manage users.

So the capability is a scope, and this migration's whole job is that `server_default`:
every pre-existing row lands on "ingest" and keeps precisely the reach it had. Only the
two console_* scopes are accepted by get_current_user, and they must be asked for at mint
time. `user_id` is the user a console key acts as — its role gates the key, so existing
per-role authz applies unchanged.

Revision ID: c1f4a9e77b02
Revises: a507191a7e3e
"""

import sqlalchemy as sa
from alembic import op

revision = "c1f4a9e77b02"
down_revision = "a507191a7e3e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default (not just a model default) so rows written by anything that bypasses
    # the ORM are grandfathered too, and so the column can be NOT NULL immediately.
    op.add_column("api_keys", sa.Column("scope", sa.String(length=32),
                                        nullable=False, server_default="ingest"))
    op.add_column("api_keys", sa.Column("user_id", sa.Integer(), nullable=True))
    # Named explicitly: SQLite needs a name to drop it again, and batch_alter_table is what
    # makes ALTER-with-constraint work there at all.
    with op.batch_alter_table("api_keys") as batch:
        batch.create_foreign_key("fk_api_keys_user_id", "users", ["user_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_constraint("fk_api_keys_user_id", type_="foreignkey")
    op.drop_column("api_keys", "user_id")
    op.drop_column("api_keys", "scope")
