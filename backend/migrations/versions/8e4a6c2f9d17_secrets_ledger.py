"""secret_sightings + secret_rotations: where a credential travelled, and rotation proof

app/secrets_ledger.py. A sighting per (keyed fingerprint of a secret value, finding), with
who, which surface and tool, when; a rotation record per secret, verified when the old
value has not been seen for a week after the rotation. Tenant-scoped, RLS like every
tenant table (copied from d0d67dc07078).

Revision ID: 8e4a6c2f9d17
Revises: 5b9d2e7a4c18
"""
import sqlalchemy as sa
from alembic import op

revision = "8e4a6c2f9d17"
down_revision = "5b9d2e7a4c18"
branch_labels = None
depends_on = None

_PREDICATE = (
    "current_setting('app.tenant_id', true) IS NULL "
    "OR current_setting('app.tenant_id', true) = '' "
    "OR tenant_id IS NULL "
    "OR tenant_id::text = current_setting('app.tenant_id', true)"
)


def _rls(t: str) -> None:
    op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
    op.execute(f"CREATE POLICY tenant_isolation ON {t} USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def upgrade() -> None:
    op.create_table(
        "secret_sightings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("secret_fp", sa.String(32), nullable=False, server_default=""),
        sa.Column("label", sa.String(64), server_default=""),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(320), server_default=""),
        sa.Column("surface", sa.String(32), server_default=""),
        sa.Column("channel", sa.String(64), server_default=""),
        sa.Column("seen_at", sa.DateTime()),
        sa.UniqueConstraint("tenant_id", "secret_fp", "finding_id", name="uq_secret_sighting"),
    )
    op.create_index("ix_secret_sightings_tenant_id", "secret_sightings", ["tenant_id"])
    op.create_index("ix_secret_sightings_secret_fp", "secret_sightings", ["secret_fp"])
    op.create_index("ix_secret_sightings_finding_id", "secret_sightings", ["finding_id"])
    op.create_index("ix_secret_sightings_seen_at", "secret_sightings", ["seen_at"])
    op.create_table(
        "secret_rotations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("secret_fp", sa.String(32), nullable=False, server_default=""),
        sa.Column("label", sa.String(64), server_default=""),
        sa.Column("rotated_at", sa.DateTime()),
        sa.Column("rotated_by", sa.String(320), server_default=""),
        sa.Column("note", sa.String(500), server_default=""),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "secret_fp", name="uq_secret_rotation"),
    )
    op.create_index("ix_secret_rotations_tenant_id", "secret_rotations", ["tenant_id"])
    if op.get_bind().dialect.name == "postgresql":
        _rls("secret_sightings")
        _rls("secret_rotations")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for t in ("secret_rotations", "secret_sightings"):
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
            op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_table("secret_rotations")
    op.drop_table("secret_sightings")
