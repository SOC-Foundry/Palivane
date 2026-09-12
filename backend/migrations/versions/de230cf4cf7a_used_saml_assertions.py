"""used_saml_assertions — SAML assertion replay cache

Single-use record of accepted SAML assertion ids (per tenant, until NotOnOrAfter) so a
captured valid SAMLResponse can't be re-POSTed within its validity window. Random revision
id per the migration-ids note; single head pinned.
"""
from alembic import op
import sqlalchemy as sa

revision = "de230cf4cf7a"
down_revision = "c8866b7307e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "used_saml_assertions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), index=True),
        sa.Column("assertion_id", sa.String(255)),
        sa.Column("expires_at", sa.DateTime(), index=True),
        sa.UniqueConstraint("tenant_id", "assertion_id", name="uq_used_saml_assertion"),
    )


def downgrade() -> None:
    op.drop_table("used_saml_assertions")
