"""Persistence model: a Finding is one analyzed item plus its verdict."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    """An organization. Owns its users and findings; the unit of data isolation."""

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(256), default="")
    created_at = Column(DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {"id": self.id, "slug": self.slug, "name": self.name}


class User(Base):
    """A member of a tenant. role is 'admin' (manage users) or 'analyst'."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    email = Column(String(320), index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="analyst")  # admin | analyst
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "role": self.role,
            "active": self.active,
        }


class ApiKey(Base):
    """A long-lived machine credential (gateway / SIEM clients). Only the hash is stored."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    label = Column(String(128), default="")
    prefix = Column(String(16), index=True, nullable=False)
    token_hash = Column(String(64), nullable=False)
    actor = Column(String(320), default="")  # identity to attribute findings to
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "prefix": self.prefix,
            "actor": self.actor, "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class LoginAttempt(Base):
    """A failed login, for brute-force throttling. DB-backed so the limit holds across
    workers/replicas (multi-tenant SaaS). Rows are pruned past the throttle window."""

    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(320), index=True, nullable=False)
    ip = Column(String(64), index=True, default="")
    created_at = Column(DateTime, default=_utcnow, index=True)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)

    # Submitted content
    channel = Column(String(32), default="llm")
    surface = Column(String(32), default="llm_io", index=True)  # llm_io | ai_usage
    sender = Column(String(512), default="")
    subject = Column(String(1024), default="")
    content = Column(Text, default="")

    # Verdict
    risk_score = Column(Integer, default=0, index=True)
    severity = Column(String(32), default="benign", index=True)
    recommended_action = Column(String(32), default="allow")
    ai_generated = Column(Boolean, default=False, index=True)
    attack_intent = Column(Boolean, default=False, index=True)

    # Full signal breakdown
    signals = Column(JSON, default=list)
    judge_used = Column(Boolean, default=False)

    # Analyst workflow
    status = Column(String(32), default="open", index=True)  # open | triaged | dismissed

    def to_summary(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "channel": self.channel,
            "surface": self.surface,
            "sender": self.sender,
            "subject": self.subject,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "ai_generated": self.ai_generated,
            "attack_intent": self.attack_intent,
            "status": self.status,
            "judge_used": self.judge_used,
        }

    def to_detail(self) -> dict:
        d = self.to_summary()
        d["content"] = self.content
        d["signals"] = self.signals or []
        return d
