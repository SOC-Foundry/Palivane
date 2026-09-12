"""finding.investigation — persisted read-only analyst report

Stores the last analyst investigation on the finding ({summary, assessment,
related_activity, recommended_action, rationale, confidence, by, at}) so it survives a
reload, shows without re-running the model, and becomes part of the record. Nullable/additive.

Revision id is random (hand-rolled ids have collided here before — see the migration-ids
note); down_revision pins the single head at authoring time.
"""
from alembic import op
import sqlalchemy as sa

revision = "7f131987beb2"
down_revision = "e5a71c0b93df"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("investigation", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "investigation")
