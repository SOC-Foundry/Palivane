"""Per-tenant admin audit trail — record security-relevant actions and read them back.

`record()` is best-effort: an audit write must never break the action it's logging, so
failures are swallowed (rolled back) rather than raised.

Details are REDACTED (`redact()`) both when written and when read. The audit trail records
that a credential changed, never its value: those settings are write-only everywhere else
(the API never returns them), and the trail is readable by every admin and by read-only
console keys. Recording `PATCH /api/tenant`'s body verbatim put the SIEM token, the S3
secret, the inference-hook secret and token-bearing webhook URLs there in plain text.
"""
from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .models import AuditLog

# Settings that ARE credentials: recorded as "(set)" / "(cleared)", never by value.
SECRET_FIELDS = frozenset({"siem_token", "siem_s3_secret", "siem_s3_key_id",
                           "inference_hook_secret", "password", "client_secret"})
# URLs that can CARRY a credential (a Slack/Teams webhook URL is its own secret; a SIEM URL
# can hold a token in its path or query): recorded as their host only.
URL_FIELDS = frozenset({"alert_webhook", "siem_url"})
_MARKERS = frozenset({"(set)", "(cleared)"})


def _host(url) -> str:
    if not url:
        return "(cleared)"
    if "://" not in str(url):
        return str(url)        # already reduced to a host (or a redaction marker)
    try:
        return urlparse(str(url)).hostname or "(set)"
    except ValueError:
        return "(set)"


def redact(detail):
    """A copy of an audit detail with credentials replaced. Nested dicts are walked; every
    other value passes through unchanged. Safe on anything (non-dicts are returned as is),
    and idempotent: rows are redacted on write AND on read, so an existing marker is kept
    ("(cleared)" is a non-empty string, and must not read back as "(set)")."""
    if not isinstance(detail, dict):
        return detail
    out = {}
    for k, v in detail.items():
        if k in URL_FIELDS:
            out[k] = _host(v)
        elif k in SECRET_FIELDS:
            out[k] = v if v in _MARKERS else ("(set)" if v else "(cleared)")
        else:
            out[k] = redact(v)
    return out


def record(db: Session, tenant_id: int | None, actor: str, action: str,
           target: str = "", detail: dict | None = None) -> None:
    if tenant_id is None:
        return
    try:
        db.add(AuditLog(tenant_id=tenant_id, actor=actor or "", action=action,
                        target=target or "", detail=redact(detail or {})))
        db.commit()
    except Exception:
        db.rollback()


def recent(db: Session, tenant_id: int, limit: int = 100, action: str | None = None) -> list[dict]:
    q = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if action:
        q = q.filter(AuditLog.action == action)
    rows = q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(min(limit, 500)).all()
    return [r.to_dict() for r in rows]
