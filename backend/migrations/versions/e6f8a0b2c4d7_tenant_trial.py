"""tenants: trial_ends_at (hosted 14-day trial replaces the free tier)

Existing tenants are deliberately NOT put on a trial clock: plan stays whatever it is and
trial_ends_at stays NULL, so nobody who signed up under the old free tier loses access
because of a deploy. New hosted signups get plan="trial" (see auth.signup); moving legacy
free tenants onto a trial is an operator decision:

    python -m app.users set-plan --tenant acme --plan trial

Revision ID: e6f8a0b2c4d7
Revises: d5e7f9a1b3c6
Create Date: 2026-07-29 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e6f8a0b2c4d7'
down_revision: Union[str, None] = 'd5e7f9a1b3c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('trial_ends_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('tenants', 'trial_ends_at')
