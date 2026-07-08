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
    # Per-tenant Claude-judge consent: None = inherit global, True/False = force on/off.
    # The judge ships content to Anthropic, so an org can opt out for data-residency.
    judge_enabled = Column(Boolean, nullable=True, default=None)
    # Delete this tenant's findings older than N days (0 = keep forever).
    retention_days = Column(Integer, default=0)
    # Gateway requests allowed per minute for this org (0 = inherit global default).
    rate_limit = Column(Integer, default=0)
    # Sensor/ingest requests per minute (capture planes), counted separately from the
    # gateway so agentic tool-call volume can't starve real LLM traffic (0 = inherit global).
    ingest_rate_limit = Column(Integer, default=0)
    # Approved MCP server hosts for this org (comma-separated). Empty = inherit the global
    # MCP_ALLOWED_SERVERS; a non-empty list flags MCP activity to any server not on it.
    mcp_allowed_servers = Column(String(1024), default="")
    # Supply-chain allow/deny lists (comma-separated). Empty = inherit the global env default.
    ide_ext_allowed = Column(String(2048), default="")
    ide_ext_denylist = Column(String(2048), default="")
    dep_denylist = Column(String(2048), default="")
    # Alerting: POST high/critical findings to this webhook (Slack-compatible {"text":…}).
    alert_webhook = Column(String(1024), default="")
    alert_min_severity = Column(String(16), default="high")
    # Digest mode: "off" = real-time per finding; "hourly"/"daily" = batch alertable findings
    # into a rollup (criticals still fire real-time). alert_digest_last tracks the window.
    alert_digest = Column(String(16), default="off")
    alert_digest_last = Column(DateTime, nullable=True)
    # SIEM forwarding: push findings >= siem_min_severity to a collector (Splunk HEC / generic
    # HTTP / CEF). Vendor-neutral — the SIEM specifics are the customer's URL + token + format.
    siem_url = Column(String(1024), default="")
    siem_token = Column(String(1024), default="")     # bearer / HEC token (write-only via API)
    siem_min_severity = Column(String(16), default="high")
    siem_format = Column(String(16), default="json")  # json | splunk_hec | cef
    # Per-tenant policy posture (each org picks its own monitor/enforce stance; empty/None
    # = inherit the global env default, same tri-state pattern as judge_enabled).
    gateway_enforce = Column(Boolean, nullable=True, default=None)
    gateway_block_severity = Column(String(16), default="")
    # Block threshold for capture-plane verdicts (/api/ingest/mcp action). Empty = global.
    mcp_block_severity = Column(String(16), default="")
    # Org-approved AI destinations (comma-separated hosts). Empty = inherit global.
    sanctioned_ai_tools = Column(String(2048), default="")
    # Per-tool signal suppression ("tool:category;tool:category"). Empty = inherit global.
    tool_suppress = Column(String(2048), default="")
    # Org-specific PII / confidential patterns ("label=regex" per line): customer IDs,
    # account numbers, MRNs, project codenames. Applied on top of the built-in PII set.
    custom_pii_patterns = Column(String(4096), default="")
    # Data-processing agreement acceptance (compliance record; history in the audit log).
    dpa_version = Column(String(32), default="")
    dpa_accepted_at = Column(DateTime, nullable=True)
    dpa_accepted_by = Column(String(320), default="")

    def to_dict(self) -> dict:
        return {"id": self.id, "slug": self.slug, "name": self.name,
                "judge_enabled": self.judge_enabled, "retention_days": self.retention_days,
                "rate_limit": self.rate_limit, "ingest_rate_limit": self.ingest_rate_limit or 0,
                "mcp_allowed_servers": self.mcp_allowed_servers or "",
                "ide_ext_allowed": self.ide_ext_allowed or "",
                "ide_ext_denylist": self.ide_ext_denylist or "",
                "dep_denylist": self.dep_denylist or "",
                # alert_webhook can embed a secret (Slack token in the URL) — write-only,
                # like siem_token; expose only whether one is configured.
                "alert_webhook_set": bool((self.alert_webhook or "").strip()),
                "alert_min_severity": self.alert_min_severity or "high",
                "alert_digest": self.alert_digest or "off",
                # siem_token is write-only — never returned; expose whether one is set.
                "siem_url": self.siem_url or "",
                "siem_min_severity": self.siem_min_severity or "high",
                "siem_format": self.siem_format or "json",
                "siem_token_set": bool((self.siem_token or "").strip()),
                "gateway_enforce": self.gateway_enforce,
                "gateway_block_severity": self.gateway_block_severity or "",
                "mcp_block_severity": self.mcp_block_severity or "",
                "sanctioned_ai_tools": self.sanctioned_ai_tools or "",
                "custom_pii_patterns": self.custom_pii_patterns or "",
                "tool_suppress": self.tool_suppress or "",
                "dpa_version": self.dpa_version or "",
                "dpa_accepted_at": self.dpa_accepted_at.isoformat() if self.dpa_accepted_at else None,
                "dpa_accepted_by": self.dpa_accepted_by or ""}


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
    # Bumped to revoke all of this user's existing session tokens ("log out everywhere").
    token_version = Column(Integer, default=0, nullable=False)
    # MFA (TOTP): secret is encrypted at rest; recovery codes stored as sha256 hashes.
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(Text, default="")
    mfa_recovery = Column(JSON, default=list)
    created_at = Column(DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "role": self.role,
            "active": self.active,
            "mfa_enabled": self.mfa_enabled,
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


class EnrollmentToken(Base):
    """A tenant-scoped token a device presents once to self-register and receive its own
    per-device API key. Only the hash is stored; supports expiry and a max-use cap."""

    __tablename__ = "enrollment_tokens"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    label = Column(String(128), default="")
    prefix = Column(String(16), index=True, nullable=False)
    token_hash = Column(String(64), nullable=False)
    active = Column(Boolean, default=True)
    max_uses = Column(Integer, nullable=True)   # None = unlimited
    uses = Column(Integer, default=0)
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "prefix": self.prefix,
            "active": self.active, "max_uses": self.max_uses, "uses": self.uses,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class TenantUpstream(Base):
    """Per-tenant LLM provider config for the gateway — so each org's allowed calls
    forward with *its own* provider account/key (billing isolation in multi-tenant SaaS).
    The key is stored encrypted; falls back to the global env config when absent."""

    __tablename__ = "tenant_upstreams"
    __table_args__ = (UniqueConstraint("tenant_id", "provider", name="uq_upstream_tenant_provider"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    provider = Column(String(32), nullable=False)   # openai | anthropic | gemini
    base_url = Column(String(512), default="")
    key_encrypted = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class AuditLog(Base):
    """A security-relevant admin action, for the per-tenant audit trail (who did what,
    when). Append-only; scoped to a tenant."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=_utcnow, index=True)
    actor = Column(String(320), default="")     # who performed it (user email)
    action = Column(String(64), default="")      # e.g. user.create, oidc.update
    target = Column(String(320), default="")     # what it affected (email/provider/label)
    detail = Column(JSON, default=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "actor": self.actor, "action": self.action,
            "target": self.target, "detail": self.detail or {},
        }


class GatewayUsage(Base):
    """Per-tenant, per-minute request counter, split by `kind` (gateway vs sensor ingest)
    so high-volume agentic capture never starves the gateway budget. Doubles as the
    rate-limit window (count this minute vs the tenant's limit for that kind) and the
    metering source. One row per tenant per minute per kind; old rows pruned."""

    __tablename__ = "gateway_usage"
    __table_args__ = (UniqueConstraint("tenant_id", "window_start", "kind",
                                       name="uq_usage_tenant_window_kind"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    window_start = Column(DateTime, index=True, nullable=False)  # minute-truncated
    kind = Column(String(16), default="gateway", nullable=False)  # "gateway" | "ingest"
    count = Column(Integer, default=0, nullable=False)


class TenantOIDC(Base):
    """Per-tenant OpenID Connect (SSO) config. One IdP per tenant; client secret stored
    encrypted. `auto_provision` creates an analyst on first SSO login; `allowed_domain`
    optionally restricts which email domains may sign in."""

    __tablename__ = "tenant_oidc"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), unique=True, index=True, nullable=False)
    issuer = Column(String(512), default="")
    client_id = Column(String(512), default="")
    client_secret_encrypted = Column(Text, default="")
    enabled = Column(Boolean, default=False)
    auto_provision = Column(Boolean, default=True)
    allowed_domain = Column(String(256), default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class TenantSAML(Base):
    """Per-tenant SAML 2.0 SSO config (we're the SP). One IdP per tenant."""

    __tablename__ = "tenant_saml"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), unique=True, index=True, nullable=False)
    idp_entity_id = Column(String(512), default="")
    idp_sso_url = Column(String(512), default="")
    idp_x509_cert = Column(Text, default="")     # IdP signing cert (public; not a secret)
    enabled = Column(Boolean, default=False)
    auto_provision = Column(Boolean, default=True)
    allowed_domain = Column(String(256), default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


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
        from .crypto import unseal
        d = self.to_summary()
        d["content"] = unseal(self.content)   # decrypt if stored encrypted
        d["signals"] = self.signals or []
        return d
