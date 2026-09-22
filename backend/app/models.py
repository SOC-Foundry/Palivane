"""Persistence model: a Finding is one analyzed item plus its verdict."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from .database import Base
from .signal_summary import top_signals


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
    # BYOK judge: the org's own judge API key (encrypted, write-only). When set, the
    # judge runs for this tenant on THEIR key and bill — independent of the operator's
    # judge capacity and exempt from the plan gate (they're paying for the inference).
    judge_byok_provider = Column(String(16), default="")   # anthropic | openai | gemini
    judge_byok_key_encrypted = Column(Text, default="")
    judge_byok_model = Column(String(128), default="")     # empty = provider default
    # Delete this tenant's findings older than N days (0 = keep forever).
    retention_days = Column(Integer, default=0)
    # Gateway requests allowed per minute for this org (0 = inherit global default).
    rate_limit = Column(Integer, default=0)
    # Sensor/ingest requests per minute (capture planes), counted separately from the
    # gateway so agentic tool-call volume can't starve real LLM traffic (0 = inherit global).
    ingest_rate_limit = Column(Integer, default=0)
    # Resource quotas (0 = inherit the PALIVANE_QUOTA_* global). Operator-set only — not
    # writable through the tenant API, or orgs could raise their own caps.
    quota_users = Column(Integer, default=0)
    quota_api_keys = Column(Integer, default=0)
    quota_ingest_per_day = Column(Integer, default=0)
    # Self-serve billing (app/billing.py): the Stripe customer this org maps to, and its
    # live subscription (empty = none). Plan changes ride the webhook, never the client.
    stripe_customer_id = Column(String(64), default="")
    stripe_subscription_id = Column(String(64), default="")
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
    # Weekly exec report by email (to the org's admins): findings by severity, newly
    # discovered AI tools, top actors. weekly_report_last is the send-window claim.
    weekly_report = Column(Boolean, default=False)
    weekly_report_last = Column(DateTime, nullable=True)
    # SIEM forwarding: push findings >= siem_min_severity to a collector (Splunk HEC / generic
    # HTTP / CEF). Vendor-neutral — the SIEM specifics are the customer's URL + token + format.
    siem_url = Column(String(1024), default="")
    # Bearer / HEC token: write-only via the API and sealed at rest (crypto.seal, enc:v1:
    # tag). Width covers a 1024-char raw token after Fernet + base64 expansion.
    siem_token = Column(String(2048), default="")
    siem_min_severity = Column(String(16), default="high")
    siem_format = Column(String(16), default="json")  # json | splunk_hec | cef
    # SIEM/data-lake delivery to S3 (independent of the HTTP push above): batched-ish per-
    # finding JSON objects to a bucket a Panther S3 log source / Athena / Snowflake can ingest.
    siem_s3_bucket = Column(String(255), default="")
    siem_s3_prefix = Column(String(255), default="")
    siem_s3_region = Column(String(32), default="")
    siem_s3_key_id = Column(String(128), default="")   # AWS access key id (write-only via API)
    # AWS secret access key: write-only via the API and sealed at rest (crypto.seal).
    siem_s3_secret = Column(String(512), default="")
    # Cross-account delivery via STS AssumeRole — the preferred auth over static keys
    # (no long-lived secret stored; the customer can revoke by editing their trust
    # policy). The customer's role trusts this deployment's AWS principal
    # (PALIVANE_AWS_DELIVERY_PRINCIPAL), scoped by a per-tenant external ID (generated
    # server-side; a confused-deputy guard, not a secret). Role takes precedence over
    # the key pair when both are set.
    siem_s3_role_arn = Column(String(512), default="")
    siem_s3_external_id = Column(String(64), default="")
    # Raw event archival to the same S3 sink (archive_s3.py): EVERY analyzed event (benign
    # included) as NDJSON micro-batches under <prefix>/<naming>/events/… — the audit-trail
    # complement to the findings feed above. Content ships redacted unless the org opts
    # into raw prose; daily_mb caps bytes/day (0 = the PALIVANE_ARCHIVE_DAILY_MB default).
    archive_s3_enabled = Column(Boolean, default=False)
    archive_s3_raw_content = Column(Boolean, default=False)
    archive_s3_daily_mb = Column(Integer, default=0)
    # Per-tenant policy posture (each org picks its own monitor/enforce stance; empty/None
    # = inherit the global env default, same tri-state pattern as judge_enabled).
    gateway_enforce = Column(Boolean, nullable=True, default=None)
    gateway_block_severity = Column(String(16), default="")
    # Local capture planes (CLI hooks + desktop egress proxy): the org's monitor/enforce
    # stance, returned to clients in ingest verdicts and provisioned at connect time.
    # None = inherit the global CLIENT_ENFORCE env default (monitor).
    client_enforce = Column(Boolean, nullable=True, default=None)
    # Coaching mode (tri-state, None = inherit global PALIVANE_REDACT_MODE). On = a
    # redactable data-loss block becomes a warn showing the cleaned prompt + a sanctioned-
    # tool redirect, keeping the user in the loop instead of a hard stop.
    redact_mode = Column(Boolean, nullable=True, default=None)
    # Self-service justification (tri-state, None = inherit global PALIVANE_SELF_JUSTIFY).
    # On = a blocked user may record a business justification and proceed immediately —
    # the justification lands on the finding (owner_response) and in the audit log, so
    # enforcement teaches instead of ticket-queueing. Confirmed secret/PII leaks
    # (force_block) are NEVER self-overridable.
    self_justify = Column(Boolean, nullable=True, default=None)
    # SCIM 2.0 provisioning: SHA-256 of the org's bearer token (plaintext shown once at
    # mint; minting again rotates). Empty = SCIM is off for the org.
    scim_token_hash = Column(String(64), default="")
    # Per-org gateway tokenization (tri-state; NULL inherits GATEWAY_TOKENIZE). Separate
    # from the global because turning it on changes what a provider receives, so it has to
    # be possible to pilot on one org rather than all of them at once.
    gateway_tokenize = Column(Boolean, nullable=True, default=None)
    # Block threshold for capture-plane verdicts (/api/ingest/mcp action). Empty = global.
    mcp_block_severity = Column(String(16), default="")
    # Block threshold for CI-runner scans (/api/scan/ci action -> palivane-ci-scan exit code).
    # Empty = inherit the global CI_BLOCK_SEVERITY, which defaults to `critical`: confirmed
    # exposure (pwn-request, secrets handed to an agent) fails a build, while posture debt
    # (unpinned actions, write-all) warns — a gate on pre-existing debt gets switched off.
    ci_block_severity = Column(String(16), default="")
    # Org-approved AI destinations (comma-separated hosts). Empty = inherit global.
    sanctioned_ai_tools = Column(String(2048), default="")
    # Per-tool signal suppression ("tool:category;tool:category"). Empty = inherit global.
    tool_suppress = Column(String(2048), default="")
    # Org-specific PII / confidential patterns ("label=regex" per line): customer IDs,
    # account numbers, MRNs, project codenames. Applied on top of the built-in PII set.
    custom_pii_patterns = Column(String(4096), default="")
    # Detection checks the admin has turned OFF (comma-separated policy keys). Empty = all on.
    disabled_checks = Column(String(2048), default="")
    # Need-to-know rules for oversharing detection ("category|kw:word = allowed_glob,…" per
    # line): flags an LLM response returning restricted data to an unauthorized recipient.
    oversharing_rules = Column(String(4096), default="")
    # Agent workload identity (OIDC): trust JWTs from this issuer as agent credentials.
    # jwks is optional (discovered from the issuer when blank); audience is validated if set.
    agent_oidc_issuer = Column(String(512), default="")
    agent_oidc_jwks = Column(String(512), default="")
    agent_oidc_audience = Column(String(255), default="")
    # When agent OIDC is configured, block tool calls whose agent isn't OIDC-attested (a
    # bearer ag_ token or none). Off = flag only. Meaningless without agent_oidc_issuer.
    agent_attestation_enforce = Column(Boolean, default=False)
    # Opt-in for the read-only AI analyst. OFF by default: investigating a finding sends its
    # redacted context out, so it stays off until an admin turns it on. It also needs a BYOK
    # judge key — the analyst has no operator-provider fallback (service.resolve_analyst_backends).
    analyst_enabled = Column(Boolean, default=False)
    # Data-processing agreement acceptance (compliance record; history in the audit log).
    dpa_version = Column(String(32), default="")
    dpa_accepted_at = Column(DateTime, nullable=True)
    dpa_accepted_by = Column(String(320), default="")
    # Lifecycle: "active" | "suspended". Suspension is operator-set (CLI) and blocks
    # logins, sessions, ingest, and the gateway without touching any data.
    status = Column(String(16), default="active", nullable=False)
    # Licensing tier: "free" | "team" | "enterprise" (see app/plans.py). Operator-set
    # only — upgrades are sales-led; there is no API for an org to raise its own plan.
    plan = Column(String(16), default="free", nullable=False)
    # When a hosted trial lapses (plan="trial"). NULL = no clock: that is every
    # self-hosted/free tenant, and an operator can clear it to extend a trial indefinitely.
    trial_ends_at = Column(DateTime, nullable=True)
    # Highest trial-lifecycle notice already emailed ("" | d7 | d2 | expired) — the dedupe
    # marker for app/trial.py, claimed via conditional update so workers can't double-send.
    trial_notice = Column(String(16), default="", nullable=False)
    # Persist raw prompt prose in this tenant's findings? None = inherit the global default
    # (PALIVANE_STORE_CONTENT, off). Off = metadata-only (verdict + signals + redacted
    # evidence, no natural-language content).
    store_content = Column(Boolean, nullable=True, default=None)
    # Per-tenant data key (DEK) wrapped by the master KEK — content is enc:v2: sealed under
    # it. Generated lazily on first content store. Dropping this revokes the tenant's content.
    dek_wrapped = Column(Text, default="")
    # Consented ML-corpus capture (docs/ml-classifier-baseline.md): stage a sample of this
    # tenant's scanned gateway prompts for analyst labeling. Deliberately NOT tri-state —
    # consent to contribute prompt prose must be an explicit per-tenant opt-in, never
    # inherited from a global default. Off unless the org turns it on.
    ml_capture = Column(Boolean, default=False)

    def to_dict(self) -> dict:
        from .config import settings as _settings   # late: test_config.py rebinds it
        from .plans import PLANS, features_of, plan_of, trial_days_left
        return {"id": self.id, "slug": self.slug, "name": self.name,
                "status": self.status or "active",
                "plan": plan_of(self),
                "plan_label": PLANS[plan_of(self)]["label"],
                # Non-null only on a hosted trial — drives the console's countdown banner.
                "trial_ends_at": self.trial_ends_at.isoformat() if self.trial_ends_at else None,
                "trial_days_left": trial_days_left(self),
                # Client-side hints for the console (lock badges); the API is the authority.
                "plan_features": features_of(self),
                "store_content": self.store_content,
                "ml_capture": bool(self.ml_capture),
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
                "weekly_report": bool(self.weekly_report),
                # siem_token is write-only — never returned; expose whether one is set.
                "siem_url": self.siem_url or "",
                "siem_min_severity": self.siem_min_severity or "high",
                "siem_format": self.siem_format or "json",
                "siem_s3_bucket": self.siem_s3_bucket or "",
                "siem_s3_prefix": self.siem_s3_prefix or "",
                "siem_s3_region": self.siem_s3_region or "",
                # Role-based delivery config is not secret (the ARN names the customer's
                # own role; the external ID only guards confused-deputy) — returned so
                # the console can render it, unlike the write-only key pair.
                "siem_s3_role_arn": self.siem_s3_role_arn or "",
                "siem_s3_external_id": self.siem_s3_external_id or "",
                # creds are write-only; expose only whether S3 delivery is fully
                # configured (a role this deployment can actually assume, or the full
                # static key pair).
                "siem_s3_configured": bool((self.siem_s3_bucket or "").strip()
                                           and (((self.siem_s3_role_arn or "").strip()
                                                 and _settings.role_delivery_principal)
                                                or ((self.siem_s3_key_id or "").strip()
                                                    and (self.siem_s3_secret or "").strip()))),
                "archive_s3_enabled": bool(self.archive_s3_enabled),
                "archive_s3_raw_content": bool(self.archive_s3_raw_content),
                "archive_s3_daily_mb": self.archive_s3_daily_mb or 0,
                "siem_token_set": bool((self.siem_token or "").strip()),
                "gateway_enforce": self.gateway_enforce,
                "client_enforce": self.client_enforce,
                "redact_mode": self.redact_mode,
                "self_justify": self.self_justify,
                "scim_enabled": bool(self.scim_token_hash),
                "gateway_tokenize": self.gateway_tokenize,
                "gateway_block_severity": self.gateway_block_severity or "",
                "mcp_block_severity": self.mcp_block_severity or "",
                "ci_block_severity": self.ci_block_severity or "",
                "sanctioned_ai_tools": self.sanctioned_ai_tools or "",
                "custom_pii_patterns": self.custom_pii_patterns or "",
                "tool_suppress": self.tool_suppress or "",
                "disabled_checks": [c for c in (self.disabled_checks or "").split(",") if c],
                "oversharing_rules": self.oversharing_rules or "",
                "agent_oidc_issuer": self.agent_oidc_issuer or "",
                "agent_oidc_jwks": self.agent_oidc_jwks or "",
                "agent_oidc_audience": self.agent_oidc_audience or "",
                "agent_attestation_enforce": bool(self.agent_attestation_enforce),
                "analyst_enabled": bool(self.analyst_enabled),
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
    # Mailbox proven. Default True (existing/CLI-created/invited users are trusted); a
    # self-serve NEW-ORG signup is created False when the email plane is on and can't log
    # in until the emailed verify link is clicked. False blocks login.
    email_verified = Column(Boolean, default=True, nullable=False)
    # Bumped to revoke all of this user's existing session tokens ("log out everywhere").
    token_version = Column(Integer, default=0, nullable=False)
    # MFA (TOTP): secret is encrypted at rest; recovery codes stored as sha256 hashes.
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(Text, default="")
    mfa_recovery = Column(JSON, default=list)
    # Highest accepted TOTP time-step — a code at/below this is a replay and is refused.
    mfa_last_step = Column(Integer, default=0, nullable=False)
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


# What an api_key is allowed to reach. Historically every key was an ingest credential for
# the gateway/SIEM planes, and NOTHING more — so the console API deliberately refused them.
# Adding console access to that same credential type would have silently promoted every key
# already in the field into an admin-capable one, so the capability is a scope, every
# pre-existing row is grandfathered to "ingest", and only the two console_* scopes are
# accepted by get_current_user.
API_KEY_SCOPES = ("ingest", "console_read", "console_write")
CONSOLE_SCOPES = ("console_read", "console_write")


class ApiKey(Base):
    """A long-lived machine credential. `scope` decides which plane it can reach: "ingest"
    (the original: gateway + SIEM, never the console API) or console_read/console_write —
    see API_KEY_SCOPES. A console key also carries `user_id`: it acts AS that user, so every
    existing per-role authz check applies to it unchanged instead of being re-derived here.
    Only the hash is stored."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    label = Column(String(128), default="")
    # "ingest" (default, and what every pre-scope key is) | "console_read" | "console_write".
    scope = Column(String(32), default="ingest", nullable=False)
    # The user a console key acts as — its role gates what the key can do. NULL for ingest
    # keys, which have no user identity at all.
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    prefix = Column(String(16), index=True, nullable=False)
    token_hash = Column(String(64), nullable=False)
    actor = Column(String(320), default="")  # identity to attribute findings to
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    last_used_at = Column(DateTime, nullable=True)
    # Stamped when a client presents this key AFTER it was revoked/expired — the fleet
    # view surfaces these as "device still presenting a dead key" (otherwise a rotated
    # device fails open silently and looks identical to a healthy quiet one).
    last_failed_at = Column(DateTime, nullable=True)
    # Fleet alerting: when the "device still presenting a dead key" alert went out for
    # this key (once per key, not per sweep). See alerts.run_fleet_alerts.
    dead_alerted_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "prefix": self.prefix,
            "actor": self.actor, "active": self.active,
            "scope": self.scope or "ingest", "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "last_failed_at": self.last_failed_at.isoformat() if self.last_failed_at else None,
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


class TenantDomain(Base):
    """An email domain claimed by a tenant (verified via DNS TXT). Once verified, a
    self-serve signup whose email matches routes to a JoinRequest for this tenant instead
    of creating a duplicate single-user org. `domain` is globally unique — first verified
    claim wins. Free-mail domains (gmail etc.) can never be claimed."""

    __tablename__ = "tenant_domains"
    __table_args__ = (UniqueConstraint("domain", name="uq_tenant_domain"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    domain = Column(String(255), nullable=False)          # lowercase, no leading dot
    token = Column(String(64), nullable=False)            # value of the DNS TXT record
    verified = Column(Boolean, default=False, nullable=False)
    # Approve matching join requests automatically (domain ownership is proven, but the
    # requester's control of the mailbox is NOT — leave off unless that risk is acceptable).
    auto_approve = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    verified_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "domain": self.domain, "verified": self.verified,
            "auto_approve": self.auto_approve, "token": self.token,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }


class JoinRequest(Base):
    """A signup that matched a claimed domain: the would-be user's email + chosen password
    (hash only), parked until a tenant admin approves. Approval creates the User with the
    stored hash — no email round-trip needed (there is no outbound email plane yet)."""

    __tablename__ = "join_requests"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_join_tenant_email"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    email = Column(String(320), nullable=False)
    password_hash = Column(String(256), nullable=False)
    status = Column(String(16), default="pending", nullable=False)  # pending|approved|denied
    # True once the requester clicked the emailed confirm link — i.e. mailbox ownership is
    # proven. Stays False (and is shown to the approving admin) when email is disabled.
    email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    decided_at = Column(DateTime, nullable=True)
    decided_by = Column(String(320), default="")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "email": self.email, "status": self.status,
            "email_verified": self.email_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decided_by": self.decided_by,
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
    auto_provision = Column(Boolean, default=False)  # safe default: don't auto-create accounts unless opted in
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
    auto_provision = Column(Boolean, default=False)  # safe default: don't auto-create accounts unless opted in
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
    # The console queue's hot path: newest activity first within a tenant.
    __table_args__ = (Index("ix_findings_tenant_last_seen", "tenant_id", "last_seen"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)

    # Submitted content
    channel = Column(String(32), default="llm")
    surface = Column(String(32), default="llm_io", index=True)  # llm_io | ai_usage
    sender = Column(String(512), default="")
    subject = Column(String(1024), default="")
    agent = Column(String(128), default="", index=True)  # resolved AI-agent identity, if any
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

    # Recurrence folding: repeats of the same event signature (same actor/tool/signals)
    # bump seen_count/last_seen on the first row instead of piling up new open rows.
    fingerprint = Column(String(64), default="", index=True)
    seen_count = Column(Integer, default=1)
    last_seen = Column(DateTime, default=_utcnow)
    # Content-origin match (app/content_origin.py): when leaked prompt content overlaps a
    # document Palivane scanned at rest, the source is attached here —
    # {source, ref, title, owner, containment}. Empty when no origin matched.
    origin = Column(JSON, default=None)
    # What the person this finding belongs to said about it: {action, note, by, at}.
    # Written only through /api/my/findings/{id}/respond, which requires the caller to BE
    # that person. An answer, not a verdict: responding never dismisses a finding, so a
    # real leak cannot be closed by the one person with a reason to want it closed.
    owner_response = Column(JSON, default=None)
    # The read-only analyst agent's last investigation of this finding: {summary, assessment,
    # related_activity, recommended_action, rationale, confidence, by, at}. Persisted so it
    # survives a reload and is part of the record; overwritten on re-investigation. Advisory —
    # it never changes status on its own (a human applies the recommendation).
    investigation = Column(JSON, default=None)

    def to_summary(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "seen_count": self.seen_count or 1,
            "categories": sorted({s.get("category", "") for s in (self.signals or [])} - {""}),
            # The strongest signals (title + redacted evidence) so a list row can show *what*
            # matched, not just the category buckets — same summary the alerts use.
            "top_signals": top_signals(self.signals, 3),
            "channel": self.channel,
            "surface": self.surface,
            "sender": self.sender,
            "subject": self.subject,
            "agent": self.agent or "",
            "risk_score": self.risk_score,
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "ai_generated": self.ai_generated,
            "attack_intent": self.attack_intent,
            "status": self.status,
            "judge_used": self.judge_used,
            # Where leaked content came from, when matched to a scanned document.
            "origin": self.origin or None,
            # The owner's own answer, if they have given one. On the summary as well as the
            # detail so an admin sees "already answered" while triaging the queue, rather
            # than opening each row to find out.
            "owner_response": self.owner_response or None,
        }

    def to_detail(self, dek: str | None = None) -> dict:
        """`dek` is the tenant's unwrapped data key, needed to open enc:v2: content;
        legacy enc:v1: content decrypts without it. content_retained reflects whether any
        prose was stored (false under the metadata-only policy)."""
        from .crypto import unseal_with
        d = self.to_summary()
        d["content"] = unseal_with(self.content, dek) if self.content else ""
        d["content_retained"] = bool(self.content)
        d["signals"] = self.signals or []
        d["investigation"] = self.investigation or None
        return d


class CorpusSample(Base):
    """One consented, sampled prompt from the live scan path, staged for analyst labeling —
    the raw material for the ML classifier's REAL training corpus (the go/no-go gate in
    docs/ml-classifier-baseline.md requires consented captures, analyst labels, and a
    time-windowed holdout before any model ships).

    Rows exist only for tenants that explicitly opted in (Tenant.ml_capture). Content is
    treated exactly like Finding content: redacted per PALIVANE_REDACT_FINDINGS and sealed
    under the tenant's DEK when PALIVANE_ENCRYPT_FINDINGS is on. The regex engine's verdict
    rides along as a WEAK label only; `label` starts NULL (= unlabeled) and is set solely by
    a human analyst, with attribution. Unlabeled rows age out with the content TTL —
    unreviewed prose is exposure, not data."""

    __tablename__ = "corpus_samples"
    # created_at is the time-window holdout key (train on old windows, eval on new ones),
    # so the hot queries are (tenant, created_at) scans and the unlabeled queue.
    __table_args__ = (Index("ix_corpus_tenant_created", "tenant_id", "created_at"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    created_at = Column(DateTime, default=_utcnow, index=True)
    channel = Column(String(64), default="")         # tool that sent the prompt
    surface = Column(String(32), default="llm_io")
    content = Column(Text, default="")               # redacted + sealed like Finding.content
    # The regex engine's verdict at capture time — a weak label and a drift reference,
    # never ground truth (that would just re-teach the model the regexes).
    regex_severity = Column(String(16), default="")
    regex_score = Column(Integer, default=0)
    weak_label = Column(String(16), default="")      # injection | benign (from regex verdict)
    # Analyst ground truth. NULL = unlabeled (the labeling queue); set only by a human.
    label = Column(String(16), nullable=True, default=None)   # injection | benign
    labeled_by = Column(String(320), default="")
    labeled_at = Column(DateTime, nullable=True)

    def to_dict(self, dek: str | None = None) -> dict:
        """`dek` is the tenant's unwrapped data key (needed for enc:v2: content)."""
        from .crypto import unseal_with
        return {"id": self.id,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "channel": self.channel or "", "surface": self.surface or "llm_io",
                "content": unseal_with(self.content, dek) if self.content else "",
                "regex_severity": self.regex_severity or "",
                "regex_score": self.regex_score or 0,
                "weak_label": self.weak_label or "",
                "label": self.label,
                "labeled_by": self.labeled_by or "",
                "labeled_at": self.labeled_at.isoformat() if self.labeled_at else None}


class DiscoveredUsage(Base):
    """One (actor, AI tool) pair Palivane has observed — the substrate for shadow-AI
    discovery. Rows come from two sources:
      - `capture`: a capture plane (extension / gateway / proxy) actually saw content go
        to this tool, so we also know whether it carried sensitive data.
      - `log`: a CASB / SWG / proxy / DNS log line said this actor reached this tool. No
        content, so it's attribution only.
    Upserted (counts incremented) rather than one row per event, so the table stays small.
    Sanctioned/unsanctioned is NOT stored — it's derived at query time from the tenant's
    allowlist, so changing the policy re-classifies the whole inventory instantly."""

    __tablename__ = "discovered_usage"
    __table_args__ = (UniqueConstraint("tenant_id", "actor", "tool", name="uq_usage_actor_tool"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    actor = Column(String(320), default="", index=True)   # normalized (lowercased) user id
    team = Column(String(128), default="")                # department/team, if known
    tool = Column(String(128), default="", index=True)    # canonical AI tool name
    domain = Column(String(255), default="")              # catalog domain matched
    category = Column(String(32), default="")             # assistant | coding | meeting | …
    source = Column(String(16), default="log")            # log | capture
    event_count = Column(Integer, default=0)
    sensitive_count = Column(Integer, default=0)          # events that carried sensitive data
    max_risk = Column(Integer, default=0)                 # peak risk score seen (capture)
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow, index=True)
    # Whether the actor reached the tool under a CORPORATE identity (email on a tenant-
    # verified domain) or a PERSONAL one (free-mail) — the Netskope-style distinction. A
    # sanctioned tool used from a personal account is still shadow AI. "" / "unknown" when
    # the actor isn't an email or the domain isn't classifiable.
    account_type = Column(String(16), default="")         # corporate | personal | unknown


class Agent(Base):
    """A verifiable AI-agent identity within a tenant (Phase 0: identity + attribution; role
    is carried for the future least-privilege phase). Authenticates with an `ag_…` token
    (only the hash is stored) — a per-agent credential distinct from the human/tenant."""

    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_agent_tenant_name"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    name = Column(String(128), nullable=False)          # "billing-bot"
    kind = Column(String(16), default="service")        # service | interactive
    role = Column(String(64), default="")               # reserved for Phase 1 authz
    prefix = Column(String(16), index=True, default="")
    token_hash = Column(String(64), default="")
    oidc_subject = Column(String(320), default="", index=True)  # JWT sub/client_id -> this agent
    deny = Column(String(1024), default="")             # per-agent extra deny globs (tightens the role)
    # Per-agent gateway policy (Phase 1): its own req/min budget (0 = inherit the tenant's)
    # and a block-severity override — the STRICTER of agent vs tenant applies.
    rate_limit = Column(Integer, default=0)
    block_severity = Column(String(16), default="")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "kind": self.kind, "role": self.role or "",
                "prefix": self.prefix, "active": self.active,
                "oidc_subject": self.oidc_subject or "",
                "deny": [x.strip() for x in (self.deny or "").split(",") if x.strip()],
                "rate_limit": self.rate_limit or 0,
                "block_severity": self.block_severity or "",
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "last_seen": self.last_seen.isoformat() if self.last_seen else None}


class AgentRole(Base):
    """A least-privilege role for AI agents (Phase 1). Allow-lists are globs matched against
    the MCP server / tool an agent calls; `deny` wins over allow; `default_allow` is the
    posture when no allow-list matches (default: deny). `enforce=False` = monitor (log a
    would-deny finding but let it through); `enforce=True` = block the action.

    Where the tenant's IdP governs MCP server access via EMA, `allow_servers` is a
    tightening overlay on the IdP's connection grants, not the primary gate — see the
    precedence note in authz.py and docs/mcp-ema-integration.md."""

    __tablename__ = "agent_roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_agentrole_tenant_name"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    name = Column(String(64), nullable=False)
    allow_tools = Column(String(2048), default="")     # comma-sep globs (MCP tool names)
    allow_servers = Column(String(2048), default="")   # comma-sep globs (MCP servers)
    allow_commands = Column(String(2048), default="")  # comma-sep globs (shell commands)
    deny = Column(String(2048), default="")            # comma-sep globs (explicit denies)
    data_scopes = Column(String(512), default="")      # data categories the agent may access
    default_allow = Column(Boolean, default=False)     # posture when nothing matches
    enforce = Column(Boolean, default=False)           # False = monitor, True = block
    created_at = Column(DateTime, default=_utcnow)

    @staticmethod
    def _list(raw: str) -> list[str]:
        return [x.strip().lower() for x in (raw or "").split(",") if x.strip()]

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name,
                "allow_tools": self._list(self.allow_tools),
                "allow_servers": self._list(self.allow_servers),
                "allow_commands": self._list(self.allow_commands),
                "deny": self._list(self.deny),
                "data_scopes": self._list(self.data_scopes),
                "default_allow": bool(self.default_allow), "enforce": bool(self.enforce)}


class PolicyOverride(Base):
    """A per-user or per-group override of the tenant's detection policy.

    scope='user'  -> `match` is an exact actor email (case-insensitive).
    scope='group' -> `match` is a glob against the actor (e.g. '*@contractors.acme.com',
                     'alice@*', '*intern*'), so a "group" is a matching rule — it works for
                     any actor, not only registered users.

    `disabled_checks` fully REPLACES the tenant default for a matched actor (predictable:
    what you see is that actor's exact check set). A user override beats any group override;
    among groups the most specific pattern wins."""

    __tablename__ = "policy_overrides"
    __table_args__ = (UniqueConstraint("tenant_id", "scope", "match", "channel",
                                       name="uq_override_scope_match"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    scope = Column(String(8), default="user")     # user | group
    match = Column(String(320), default="")       # email (user) or glob pattern (group)
    channel = Column(String(64), default="")      # tool/channel glob ("" = any tool)
    label = Column(String(128), default="")       # friendly name, e.g. "Contractors"
    disabled_checks = Column(String(2048), default="")
    # Staged enforcement: an explicit monitor/enforce stance for the matched actor/tool.
    # None = no opinion (the tenant/global client_enforce applies); True/False force it.
    # Lets an org enforce a pilot user, group glob, or single tool while everyone else
    # stays in monitor.
    enforce = Column(Boolean, nullable=True, default=None)
    created_at = Column(DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {"id": self.id, "scope": self.scope, "match": self.match,
                "channel": self.channel or "", "label": self.label,
                "enforce": self.enforce,
                "disabled_checks": [c for c in (self.disabled_checks or "").split(",") if c]}


class SaasConnector(Base):
    """A stored credential for pulling OAuth-grant inventories live from a SaaS platform's
    admin API (Google Workspace, M365, Slack, …) — the recurring version of the one-shot
    POST /api/discovery/oauth-grants ingest. Credentials are encrypted at rest (crypto.encrypt);
    only a redacted summary ever leaves the API."""

    __tablename__ = "saas_connectors"
    __table_args__ = (UniqueConstraint("tenant_id", "platform", "label",
                                       name="uq_connector_tenant_platform_label"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    platform = Column(String(32), nullable=False)        # google_workspace | … (registry key)
    label = Column(String(128), default="")              # "prod workspace"
    credentials_enc = Column(Text, default="")           # encrypted JSON, platform-specific
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_status = Column(String(16), default="")    # ok | error | ""
    last_sync_detail = Column(String(512), default="")   # summary counts or the error
    # Incremental-scan watermark for content-scanning connectors (JSON; e.g. Slack keeps
    # a per-channel last-message-ts map so each sync pulls only new messages). Empty for
    # grant-inventory connectors, which are stateless snapshots.
    sync_state = Column(Text, default="")

    @property
    def state(self) -> dict:
        import json
        try:
            return json.loads(self.sync_state or "{}")
        except ValueError:
            return {}

    @state.setter
    def state(self, value: dict) -> None:
        import json
        self.sync_state = json.dumps(value)


    def to_dict(self) -> dict:
        return {"id": self.id, "platform": self.platform, "label": self.label or "",
                "active": self.active, "configured": bool(self.credentials_enc),
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
                "last_sync_status": self.last_sync_status or "",
                "last_sync_detail": self.last_sync_detail or "",
                # Scan options are filled in by the API, which has the session needed to
                # unwrap the tenant-sealed credential blob they live in. Empty here rather
                # than wrong: a property on this model would get "" from unseal_secret and
                # silently report every option as off.
                "options": {}}


class ContentFingerprint(Base):
    """A shingle sketch of a document Palivane scanned at rest (Drive/SharePoint/Slack/…),
    so leaked prompt content can be matched back to its source — see app/content_origin.py.
    `shingles` is a JSON list of sampled 64-bit shingle hashes (as strings); one row per
    (tenant, source, ref), updated in place on re-scan."""

    __tablename__ = "content_fingerprints"
    __table_args__ = (UniqueConstraint("tenant_id", "source", "ref",
                                       name="uq_fingerprint_tenant_source_ref"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    source = Column(String(32), default="")      # gdrive | sharepoint | slack | salesforce
    ref = Column(String(512), default="")        # stable id/path within the source
    title = Column(String(512), default="")      # human name (file name, channel)
    owner = Column(String(320), default="")      # last modifier / owner email
    shingles = Column(JSON, default=list)         # sampled shingle hashes (strings)
    # True when the source document's own at-rest scan tripped a data-loss category —
    # i.e. the doc itself holds secrets/PII. A leak matching a KNOWN-sensitive doc gets a
    # larger severity boost than one matching a merely-known doc. No manual labeling: the
    # scan that fingerprints the doc already knows whether it was sensitive.
    sensitive = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=_utcnow, index=True)


# --- OAuth 2.1 authorization server (remote MCP) -----------------------------------------
# Palivane is its own authorization server because it is its own identity provider: users,
# roles and tenants live here, and there is no external IdP every tenant shares. The MCP SDK
# supplies the protocol (PKCE verification, code exchange, metadata, DCR); these tables and
# the provider in oauth_provider.py supply persistence and the consent binding.
#
# Nothing here is reachable yet — the routes are not wired. Storage and the provider land
# first so the token mechanics can be reviewed before a browser can reach any of it.

class OAuthClient(Base):
    """A client registered through Dynamic Client Registration (RFC 7591).

    Open registration is required by MCP clients and is NOT an access grant: registering
    only says "this software exists and these are its redirect URIs". Nothing can be read
    until a real user approves it at consent, and the token that results carries that
    user's identity and no more.
    """

    __tablename__ = "oauth_clients"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(64), unique=True, index=True, nullable=False)
    # Public clients (the MCP case) authenticate with PKCE and hold no secret; the column
    # stays for confidential clients rather than being assumed absent.
    client_secret_hash = Column(String(64), default="")
    client_name = Column(String(200), default="")
    # Exact-match allowlist. Never prefix- or wildcard-matched: a loose redirect_uri check
    # is the classic way authorization codes get delivered to an attacker.
    redirect_uris = Column(Text, default="")          # newline-separated, exact match
    scope = Column(String(200), default="")
    created_at = Column(DateTime, default=_utcnow, index=True)


class OAuthCode(Base):
    """A one-time authorization code, bound to the user who approved it."""

    __tablename__ = "oauth_codes"

    id = Column(Integer, primary_key=True, index=True)
    code_hash = Column(String(64), unique=True, index=True, nullable=False)
    client_id = Column(String(64), index=True, nullable=False)
    # WHO approved. The whole point of the consent step: a code — and the token it becomes
    # — can only ever read what this user can read.
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    redirect_uri = Column(Text, default="")
    # S256 only. `plain` is accepted by the spec and defeats the purpose, so it is refused.
    code_challenge = Column(String(128), default="")
    scopes = Column(String(200), default="")
    expires_at = Column(DateTime, index=True)          # ~60s: a code is a handoff, not a token
    used_at = Column(DateTime, nullable=True)          # single use; replay must fail
    created_at = Column(DateTime, default=_utcnow)


class OAuthToken(Base):
    """An issued access or refresh token. Stored hashed, like every other credential here."""

    __tablename__ = "oauth_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    kind = Column(String(8), default="access")         # access | refresh
    client_id = Column(String(64), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    scopes = Column(String(200), default="")
    expires_at = Column(DateTime, index=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)


class SensorHeartbeat(Base):
    """Last-seen per (actor, plane, tool) — the fleet-health ledger.

    Every capture-plane call (ai-usage, mcp, posture scans) upserts its row, so the
    console can distinguish "protected and quiet" from "silently dark" (hooks fail open
    by design — without this, a revoked key or uninstalled hook looks identical to a
    healthy device that just isn't sending anything)."""

    __tablename__ = "sensor_heartbeats"
    __table_args__ = (UniqueConstraint("tenant_id", "actor", "plane", "tool",
                                       name="uq_heartbeat_scope"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    actor = Column(String(320), default="")   # who the sensor reports as (key actor/user)
    plane = Column(String(32), default="")    # ai-usage | mcp | posture | ci
    # NAMESPACE VARIES BY PLANE — this is not one vocabulary, and reading it as one was a
    # bug. ai-usage: the assistant captured ("claude-code"). mcp: the tool CALLED
    # ("ToolSearch"). posture: the scan kind ("ide-extensions"). ci: a repo. a2a: the
    # sending agent. Always filter by plane before comparing this against anything.
    tool = Column(String(64), default="")
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow, index=True)
    count = Column(Integer, default=0)
    # Client build the sensor last reported (parsed from its User-Agent, e.g.
    # "palivane-hook/1.1.0"). Lets the console spot devices running stale plumbing —
    # server-side detection updates instantly, but installed scripts don't.
    client = Column(String(48), default="")           # palivane-hook | palivane-proxy | …
    client_version = Column(String(24), default="")
    # The HOST agent the sensor ran inside, from the parenthetical of our own UA
    # ("palivane-hook/1.1.0 (claude-code/2.1.4)"). client_version says whether OUR plumbing
    # is current; this says which vendor build was live — the difference between "a hook
    # broke" and "Claude Code 2.1.4 broke it", which is the difference between an afternoon
    # and a week when a shape changes under us.
    agent = Column(String(48), default="")
    agent_version = Column(String(24), default="")
    # Shape drift. A hook that fires on a recognized event and extracts nothing is the one
    # failure this table cannot otherwise see: fail-open means the sensor keeps checking in,
    # so last_seen stays green while coverage is silently gone. Worse than going dark,
    # because dark pages someone.
    parse_miss_count = Column(Integer, default=0)
    last_parse_miss = Column(DateTime, nullable=True)
    # Fleet alerting (alerts.run_fleet_alerts): when this sensor's gone-dark alert went
    # out. NULL = not alerted; cleared when a heartbeat resumes so a NEW dark episode
    # pages again (edge-triggered, not every sweep).
    dark_alerted_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {"actor": self.actor, "plane": self.plane, "tool": self.tool,
                "agent": self.agent or "", "agent_version": self.agent_version or "",
                "parse_miss_count": self.parse_miss_count or 0,
                "last_parse_miss": self.last_parse_miss.isoformat() if self.last_parse_miss else None,
                "first_seen": self.first_seen.isoformat() if self.first_seen else None,
                "last_seen": self.last_seen.isoformat() if self.last_seen else None,
                "count": self.count, "client": self.client or "",
                "client_version": self.client_version or ""}


class ExceptionRecord(Base):
    """A block-screen exception request with review state.

    The old flow only wrote an audit row; this makes it a first-class queue an admin can
    approve (which materializes a scoped PolicyOverride) or deny — the block screen's
    "request exception" button becomes a real workflow instead of a suggestion box."""

    __tablename__ = "exception_requests"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=True)
    finding_id = Column(Integer, nullable=True)
    actor = Column(String(320), default="")
    destination = Column(String(2048), default="")
    categories = Column(String(512), default="")   # CSV of signal categories/checks
    reason = Column(String(2000), default="")
    status = Column(String(16), default="pending", index=True)  # pending|approved|denied
    created_at = Column(DateTime, default=_utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(320), default="")
    resolution_note = Column(String(512), default="")
    applied_override_id = Column(Integer, nullable=True)  # PolicyOverride created on approve

    def to_dict(self) -> dict:
        return {"id": self.id, "finding_id": self.finding_id, "actor": self.actor,
                "destination": self.destination,
                "categories": [c for c in (self.categories or "").split(",") if c],
                "reason": self.reason, "status": self.status,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
                "resolved_by": self.resolved_by,
                "resolution_note": self.resolution_note,
                "applied_override_id": self.applied_override_id}


class License(Base):
    """Vendor-issued self-hosted license registry (issuance is otherwise stateless — the
    signed WDN1 blob verifies offline). This table is the OWNER's record: what was issued,
    to whom, and whether it's still honored. Under the short-term + renewal model the
    signed blob is short-lived; the customer's instance renews against /api/license/renew,
    which consults this table — so setting status='revoked' (or letting `contract_until`
    pass) stops renewals and the instance drops to Free when its current term expires.

    Lives on the SaaS DB (the vendor operates it); unrelated to any tenant row — the `org`
    is just the licensee label baked into the blob."""

    __tablename__ = "licenses"

    id = Column(String(32), primary_key=True)       # lic_… (also embedded in the blob)
    org = Column(String(320), nullable=False)         # licensee name
    plan = Column(String(16), nullable=False)         # team | enterprise
    seats = Column(Integer, default=0)
    issued_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=False)     # current term end (the blob's expiry)
    contract_until = Column(DateTime, nullable=True)  # hard stop: renewals refused past this
    status = Column(String(16), default="active", nullable=False)   # active | revoked
    renewed_at = Column(DateTime, nullable=True)
    renew_count = Column(Integer, default=0)
    note = Column(String(512), default="")

    def to_dict(self) -> dict:
        return {"id": self.id, "org": self.org, "plan": self.plan, "seats": self.seats or 0,
                "status": self.status or "active",
                "issued_at": self.issued_at.isoformat() if self.issued_at else None,
                "expires_at": self.expires_at.isoformat() if self.expires_at else None,
                "contract_until": self.contract_until.isoformat() if self.contract_until else None,
                "renewed_at": self.renewed_at.isoformat() if self.renewed_at else None,
                "renew_count": self.renew_count or 0, "note": self.note or ""}


class UpgradeRequest(Base):
    """An org's in-console "we want to buy" record — the sales-led upgrade path until a
    billing provider exists. One pending request per tenant (the console shows its state
    instead of the form); the operator works the queue at /admin and closes rows there.
    Closing is bookkeeping only — the actual plan change stays `users set-plan` / a license."""

    __tablename__ = "upgrade_requests"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    plan = Column(String(16), nullable=False)          # team | enterprise
    seats = Column(Integer, default=0)                 # 0 = unspecified
    contact = Column(String(320), default="")          # requester's email (reply-to)
    note = Column(String(2000), default="")
    status = Column(String(16), default="pending", nullable=False)   # pending | closed
    created_at = Column(DateTime, default=_utcnow)
    closed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {"id": self.id, "plan": self.plan, "seats": self.seats or 0,
                "contact": self.contact or "", "note": self.note or "",
                "status": self.status or "pending",
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "closed_at": self.closed_at.isoformat() if self.closed_at else None}


class UsedSamlAssertion(Base):
    """Single-use record of an accepted SAML assertion, for replay protection. python3-saml
    validates signature/audience/conditions but not one-time use, so a captured valid
    SAMLResponse could be re-POSTed within its NotOnOrAfter window. We cache the assertion id
    per tenant until it expires and reject reuse; rows are pruned once past expiry."""
    __tablename__ = "used_saml_assertions"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, index=True)
    assertion_id = Column(String(255))
    expires_at = Column(DateTime, index=True)
    __table_args__ = (UniqueConstraint("tenant_id", "assertion_id",
                                       name="uq_used_saml_assertion"),)
