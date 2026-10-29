"""Scrub credentials already written into the audit log

`PATCH /api/tenant` recorded its request body as the audit detail, so the SIEM token, the S3
secret and key id, the inference-hook secret and token-bearing webhook / SIEM URLs sit in
plain text in existing `tenant.update` rows. New rows are redacted when written (and every
row when read); this rewrites the stored ones so the values are gone from the database too.

The rules are copied here rather than imported from app.audit_log on purpose: a migration
must keep doing what it did when it was written, whatever the app code later becomes.
Data-only and idempotent (a redacted row has nothing left to redact). There is no
downgrade: the values are not recoverable, which is the point.

Revision ID: 1763cbaf8910
Revises: 8658a831e84a
"""

from urllib.parse import urlparse

import sqlalchemy as sa
from alembic import op

revision = "1763cbaf8910"
down_revision = "8658a831e84a"
branch_labels = None
depends_on = None

SECRET_FIELDS = {"siem_token", "siem_s3_secret", "siem_s3_key_id", "inference_hook_secret",
                 "password", "client_secret"}
URL_FIELDS = {"alert_webhook", "siem_url"}
REDACTED = {"(set)", "(cleared)"}


def _host(url):
    if not url:
        return "(cleared)"
    if "://" not in str(url):
        return str(url)        # already reduced to a host (idempotent)
    try:
        return urlparse(str(url)).hostname or "(set)"
    except ValueError:
        return "(set)"


def _redact(detail):
    if not isinstance(detail, dict):
        return detail
    out = {}
    for k, v in detail.items():
        if k in URL_FIELDS:
            out[k] = _host(v)
        elif k in SECRET_FIELDS:
            out[k] = v if v in REDACTED else ("(set)" if v else "(cleared)")
        else:
            out[k] = _redact(v)
    return out


def upgrade() -> None:
    bind = op.get_bind()
    audit = sa.table("audit_log", sa.column("id", sa.Integer), sa.column("detail", sa.JSON))
    rows = bind.execute(sa.select(audit.c.id, audit.c.detail)).all()
    for row_id, detail in rows:
        if not isinstance(detail, dict):
            continue
        clean = _redact(detail)
        if clean != detail:
            bind.execute(sa.update(audit).where(audit.c.id == row_id).values(detail=clean))


def downgrade() -> None:
    pass    # nothing to restore: the scrubbed values are gone by design
