"""Per-tenant admin audit trail — record security-relevant actions and read them back.

`record()` is best-effort: an audit write must never break the action it's logging, so
failures are swallowed (rolled back) rather than raised.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog


def record(db: Session, tenant_id: int | None, actor: str, action: str,
           target: str = "", detail: dict | None = None) -> None:
    if tenant_id is None:
        return
    try:
        db.add(AuditLog(tenant_id=tenant_id, actor=actor or "", action=action,
                        target=target or "", detail=detail or {}))
        db.commit()
    except Exception:
        db.rollback()


def recent(db: Session, tenant_id: int, limit: int = 100, action: str | None = None) -> list[dict]:
    q = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if action:
        q = q.filter(AuditLog.action == action)
    rows = q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(min(limit, 500)).all()
    return [r.to_dict() for r in rows]
