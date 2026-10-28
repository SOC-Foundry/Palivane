"""SSO required: the org setting

`tenants.sso_required` makes the org's own IdP (OIDC or SAML) the only way in for everyone but
admins: no password sign-in, no password reset, no Google sign-in. Admins keep their
password as a break-glass route, and the setting does nothing while no SSO is enabled, so a
broken or removed IdP config can't lock an org out.

Additive, defaults off: existing orgs are untouched.

Revision ID: 8658a831e84a
Revises: 97d32d982d3b
"""

import sqlalchemy as sa
from alembic import op

revision = "8658a831e84a"
down_revision = "97d32d982d3b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("sso_required", sa.Boolean(), nullable=False,
                                       server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("tenants", "sso_required")
