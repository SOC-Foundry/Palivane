"""API request/response schemas."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# Loose email shape for identity fields that feed attribution/authorization decisions
# (not full RFC validation — just "looks like a person, not a wildcard or free-form label").
# Glob metacharacters (*?[]) are disallowed so an identity can't be crafted to game the
# fnmatch-based coverage / need-to-know rules.
_EMAIL_RE = re.compile(r"^[^@\s*?\[\]]+@[^@\s*?\[\]]+\.[^@\s*?\[\]]+$")


def _email_shaped(v: str, *, required: bool) -> str:
    v = (v or "").strip()
    if not v:
        if required:
            raise ValueError("must be an email address")
        return ""
    if len(v) > 320 or not _EMAIL_RE.match(v):
        raise ValueError("must be an email address")
    return v

Surface = Literal["llm_io", "ai_usage"]

# Upper bound on any single content field the detectors scan — generous for real prompts /
# documents, but caps CPU (regex passes) and memory on a hostile payload. A server-side
# body-size limit (main.py) backs this for fields Pydantic can't bound (e.g. free-form JSON).
MAX_CONTENT = 200_000


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENT, description="content to analyze")
    subject: str = ""            # optional label
    # 'llm_io' = prompts/responses on our own LLMs; 'ai_usage' = content bound for an AI tool.
    surface: Surface = "llm_io"
    destination: str = ""        # where the content is being sent (AI tool name or URL)
    persist: bool = True


class BatchAnalyzeRequest(BaseModel):
    items: list[AnalyzeRequest] = Field(min_length=1, max_length=500)


class AIUsageIngest(BaseModel):
    """Content a browser extension or proxy captured on its way to an external AI tool."""
    content: str = Field(min_length=1, max_length=MAX_CONTENT)
    destination: str = ""   # AI tool URL/domain
    user: str = ""          # end-user identity (from SSO/extension)
    tool: str = ""          # capturing tool id (e.g. "claude-code") for per-tool policy


class A2AIngest(BaseModel):
    """One agent-to-agent message — an orchestrator handing a sub-agent a task, or a peer
    agent's output fed to another. Scanned for a poisoned/injected instruction (OWASP
    Agentic T12) or sensitive data crossing the hop, and correlated into the receiving
    agent's session so a poisoned message → later exfiltration reads as one chain."""
    content: str = Field(min_length=1, max_length=MAX_CONTENT)   # the message body
    from_agent: str = ""     # sending agent identity
    to_agent: str = ""       # receiving agent identity — the session actor for correlation
    protocol: str = ""       # a2a | mcp-sampling | orchestrator | … (informational)


class MCPIngest(BaseModel):
    """A normalized MCP JSON-RPC activity the egress proxy captured (agentic tool-use)."""
    method: str = ""                                   # tools/call, resources/read, initialize, tools/list.result
    server: str = ""                                   # MCP server host
    tool: str = ""                                     # tool name for tools/call
    args_text: str = Field("", max_length=MAX_CONTENT)  # joined string values of the tool arguments
    resource: str = ""                                 # URI/path for resources/read
    tool_descriptions: list[str] = Field(default_factory=list, max_length=200)  # advertised tools
    transport: str = "http"                            # http | stdio | via-llm-api
    user: str = ""                                     # end-user identity
    # Local-server supply-chain verification (palivane-mcp): the wrapped command line, the
    # sha256 of its resolved binary, and how it compared to the recorded pin (TOFU).
    command: str = Field("", max_length=1024)          # wrapped command line (stdio servers)
    binary_sha256: str = Field("", max_length=64)      # sha256 of the resolved executable
    pin_status: str = ""                               # "" | new | ok | mismatch
    # EMA (enterprise-managed authorization): the Bearer credential the capture plane saw
    # on the MCP request. Inspected server-side (oidc.inspect_ema_token) to lift an
    # IdP-governed actor identity (sub/email); opaque tokens attribute as opaque-token.
    # The raw credential is never persisted — only extracted metadata reaches the finding.
    authorization: str = Field("", max_length=8192)


class MCPBatchIngest(BaseModel):
    """A batch of MCP activities from a long-lived capture client (palivane-mcp), so many
    tool calls cost one request against the tenant's ingest quota."""
    items: list[MCPIngest] = Field(min_length=1, max_length=200)


class MCPConfigScan(BaseModel):
    """An MCP configuration file (.mcp.json, Cursor/VS Code) to vet in CI or the console."""
    content: str = Field(min_length=1, max_length=MAX_CONTENT)
    path: str = ""
    record: bool = False   # persist non-clean servers as findings (off by default)


class IDEExtScan(BaseModel):
    """IDE extensions to vet — a list of ids, or a `.vscode/extensions.json` file content."""
    extensions: list[str] = Field(default_factory=list, max_length=10000)
    content: str = ""       # e.g. .vscode/extensions.json (recommendations)
    record: bool = False


class DevicePostureScan(BaseModel):
    """A device-health report from palivane-posture: capture-plane state (proxy port/
    listener, scan-breaker fail-open) and coverage gaps (WSL/containers). JSON in
    `content`; the device_posture detector derives the findings server-side."""
    content: str = Field(min_length=1, max_length=MAX_CONTENT)
    user: str = ""
    record: bool = False


class SecretAtRest(BaseModel):
    """One credential the local `palivane-secrets` scanner found at rest — METADATA ONLY.
    The raw secret never leaves the device; `masked` is a redacted preview."""
    path: str = Field(min_length=1)
    secret_types: list[str] = Field(default_factory=list)
    masked: str = ""             # e.g. "ghp_••••4f2a" — redacted preview, never the secret
    line: int = 0
    # True/False when the scanner could determine it; None = unknown (e.g. Windows ACL
    # lookup unavailable). None must NOT be read as "private" — it carries no signal.
    world_readable: bool | None = False
    verified: bool = False       # a scanner confirmed the credential is live (TruffleHog)
    source: str = ""             # detection engine: "warden" | "trufflehog" | "gitleaks" | …


class SecretScan(BaseModel):
    """A batch of at-rest credential findings from a device (from `palivane-secrets`)."""
    items: list[SecretAtRest] = Field(default_factory=list, max_length=10000)
    host: str = ""               # device identifier for attribution
    record: bool = True          # persist findings (on by default — this is the point)


class ExceptionRequest(BaseModel):
    """An end user asking their security team to allow a blocked send (from the extension)."""
    finding_id: int | None = None
    destination: str = Field("", max_length=2048)
    reason: str = Field("", max_length=2000)
    categories: list[str] = Field(default_factory=list, max_length=32)
    user: str = ""


class ScannerImport(BaseModel):
    """Raw output from a third-party secret scanner (TruffleHog / Gitleaks / GitGuardian)
    to normalize into Palivane findings. `results` may be parsed JSON or the raw string the
    tool emits (JSON array or JSONL). The raw secret is masked at ingest, never persisted."""
    tool: str = Field(min_length=1)
    results: object = None
    host: str = ""
    record: bool = True


class CodeFile(BaseModel):
    path: str = ""
    content: str = Field(max_length=MAX_CONTENT)


class CodeScanRequest(BaseModel):
    # A pre-commit hook / CI step sends the changed files; we scan each for secrets & PII.
    files: list[CodeFile] = Field(default_factory=list, max_length=2000)
    record: bool = False          # persist non-clean files as findings (off by default)


class CIScan(BaseModel):
    """GitHub Actions runner/workflow posture scan: the repo's workflow files, sent by
    `palivane-ci-scan` (from inside a runner, or sweeping repos via the GitHub API)."""
    repo: str = ""                # owner/name — provenance for findings + discovery actor
    ref: str = ""                 # branch/sha the workflows came from (informational)
    workflows: list[CodeFile] = Field(default_factory=list, max_length=500)
    record: bool = True


class S3Object(BaseModel):
    key: str = ""
    content: str = Field(default="", max_length=MAX_CONTENT)


class S3Scan(BaseModel):
    # palivane-s3-scan streams a bucket's objects here to scan for secrets/PII at rest, plus
    # whether the bucket is publicly reachable — public + sensitive is the crown-jewel case.
    bucket: str = ""
    region: str = ""
    public: bool = False          # bucket is world-readable (ACL / policy / no public-block)
    objects: list[S3Object] = Field(default_factory=list, max_length=2000)
    record: bool = False


class StatusUpdate(BaseModel):
    status: Literal["open", "triaged", "dismissed"]


class BulkStatusUpdate(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=1000)
    status: Literal["open", "triaged", "dismissed"]


# --- auth / tenancy ---

class LoginRequest(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=1)
    # Optional tenant (org slug). Required only to disambiguate an email that exists in
    # more than one org (multi-tenant hosting); single-tenant/demo login omits it.
    org: str = ""


class ForgotRequest(BaseModel):
    email: str = Field(min_length=3)
    org: str = ""   # optional disambiguation, same semantics as login


class ResetRequest(BaseModel):
    token: str = Field(min_length=10)
    password: str = Field(min_length=8)


class SignupRequest(BaseModel):
    org_name: str = Field(min_length=2, description="organization / tenant name")
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
    slug: str = ""   # optional; derived from org_name when blank


class UserCreate(BaseModel):
    email: str = Field(min_length=3)
    # Empty password = email invite: the account is created with an unguessable random
    # password and the user gets a set-password link (requires the email plane).
    password: str = ""
    role: Literal["admin", "analyst"] = "analyst"


class UserUpdate(BaseModel):
    # Both optional — change role (promote/demote), toggle login access, or both.
    role: Literal["admin", "analyst"] | None = None
    active: bool | None = None


class MFACode(BaseModel):
    code: str = ""            # a 6-digit TOTP or a recovery code


class MFAVerify(BaseModel):
    challenge: str            # the short-lived token returned by login when MFA is on
    code: str = ""


class OIDCConfig(BaseModel):
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""            # write-only; stored encrypted, never returned
    enabled: bool | None = None        # None = leave unchanged
    auto_provision: bool | None = None
    allowed_domain: str | None = None


class SAMLConfig(BaseModel):
    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_x509_cert: str = ""
    enabled: bool | None = None
    auto_provision: bool | None = None
    allowed_domain: str | None = None


class TenantUpdate(BaseModel):
    name: str | None = None
    # LLM judge for this org: "on"/"off" force it; "inherit" follows the global key.
    # None (field omitted) = leave unchanged.
    judge: Literal["on", "off", "inherit"] | None = None
    retention_days: int | None = None   # 0 = keep findings forever
    # Persist raw prompt prose in findings: "on"/"off" force it, "inherit" follows the global
    # default (off). None = leave unchanged. Off = metadata-only (recommended).
    store_content: Literal["on", "off", "inherit"] | None = None
    rate_limit: int | None = None       # gateway requests/min (0 = inherit global default)
    ingest_rate_limit: int | None = None  # sensor/ingest requests/min (0 = inherit global)
    mcp_allowed_servers: str | None = None  # comma-separated approved MCP server hosts
    ide_ext_allowed: str | None = None      # approved IDE extension ids
    ide_ext_denylist: str | None = None     # blocked IDE extension ids
    dep_denylist: str | None = None         # known-bad dependency names
    alert_webhook: str | None = None        # Slack-compatible webhook for high/critical alerts
    alert_min_severity: str | None = None   # minimum severity to alert on
    alert_digest: str | None = None         # off | hourly | daily (batch non-critical alerts)
    siem_url: str | None = None             # SIEM collector endpoint (push findings)
    siem_token: str | None = None           # bearer / Splunk-HEC token (write-only)
    siem_min_severity: str | None = None    # minimum severity to forward
    siem_format: str | None = None          # json | splunk_hec | cef
    siem_naming: str | None = None          # palivane | warden (brand key in sourcetype/S3 path)
    siem_s3_bucket: str | None = Field(None, max_length=255)   # S3 delivery bucket
    siem_s3_prefix: str | None = Field(None, max_length=255)   # key prefix
    siem_s3_region: str | None = Field(None, max_length=32)
    siem_s3_key_id: str | None = Field(None, max_length=128)   # AWS access key id (write-only)
    siem_s3_secret: str | None = Field(None, max_length=256)   # AWS secret (write-only)
    archive_s3_enabled: bool | None = None      # archive ALL events (NDJSON) to the S3 sink
    archive_s3_raw_content: bool | None = None  # ship unredacted prose (default: redacted)
    archive_s3_daily_mb: int | None = None      # daily byte budget, MB (0 = global default)
    # Policy posture (per-org monitor/enforce): "on"/"off" force it, "inherit" follows
    # the global GATEWAY_ENFORCE. Severities: "" = inherit the global threshold.
    gateway_enforce: Literal["on", "off", "inherit"] | None = None
    # Local capture planes (CLI hooks + desktop proxy): "on"/"off" force it, "inherit"
    # follows the global CLIENT_ENFORCE (default monitor).
    client_enforce: Literal["on", "off", "inherit"] | None = None
    redact_mode: Literal["on", "off", "inherit"] | None = None   # coaching mode (tri-state)
    gateway_block_severity: str | None = None  # ""|low|suspicious|high|critical
    mcp_block_severity: str | None = None      # block threshold for capture-plane verdicts
    ci_block_severity: str | None = None       # block threshold for CI-runner scans
    sanctioned_ai_tools: str | None = None     # org-approved AI destinations (comma-separated)
    tool_suppress: str | None = None           # "tool:category;tool:category" suppressions
    custom_pii_patterns: str | None = Field(None, max_length=8192)  # org PII/confidential "label=regex" per line
    disabled_checks: list[str] | None = Field(None, max_length=64)  # detection checks turned off (policy keys)
    oversharing_rules: str | None = None        # need-to-know rules ("category = allowed_glob" per line)
    agent_oidc_issuer: str | None = None         # workload-identity trust: issuer
    agent_oidc_jwks: str | None = None           # optional explicit JWKS URI (else discovered)
    agent_oidc_audience: str | None = None        # expected audience (validated if set)


class TenantDelete(BaseModel):
    confirm: str = ""   # must equal the tenant slug — guards against accidental deletion


class DPAAccept(BaseModel):
    version: str | None = None   # DPA version accepted; None = the current server version


class UpstreamConfig(BaseModel):
    base_url: str = ""
    # Write-only: the provider API key. Stored encrypted, never returned. Leave empty on
    # an update to keep the existing key (e.g. when only changing base_url).
    key: str = ""


class JudgeKeyConfig(BaseModel):
    provider: str                 # anthropic | openai | gemini
    # Write-only: the org's own judge API key. Stored encrypted, never returned. Leave
    # empty on an update to keep the existing key (e.g. when only changing the model).
    key: str = ""
    model: str = ""               # empty = the provider's default judge model


class ApiKeyCreate(BaseModel):
    label: str = ""
    actor: str = ""               # identity to attribute this key's traffic to
    expires_in_days: int | None = None


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["service", "interactive"] = "service"
    role: str = Field("", max_length=64)   # optional least-privilege role name
    oidc_subject: str = Field("", max_length=320)   # JWT sub/client_id for workload identity


class AgentUpdate(BaseModel):
    role: str | None = Field(None, max_length=64)   # assign/clear the agent's role
    deny: list[str] | None = Field(None, max_length=200)   # per-agent extra deny globs
    oidc_subject: str | None = Field(None, max_length=320)   # JWT subject mapping
    rate_limit: int | None = Field(None, ge=0)      # gateway req/min (0 = inherit tenant)
    block_severity: Literal["", "low", "suspicious", "high", "critical"] | None = None


class AgentTokenRequest(BaseModel):
    """Mint a short-lived agent session token (JWT) — the ag_ credential stays offline."""
    ttl_minutes: int = Field(60, ge=1, le=1440)


class AgentRoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    allow_tools: list[str] = Field(default_factory=list, max_length=200)
    allow_servers: list[str] = Field(default_factory=list, max_length=200)
    allow_commands: list[str] = Field(default_factory=list, max_length=200)
    deny: list[str] = Field(default_factory=list, max_length=200)
    data_scopes: list[str] = Field(default_factory=list, max_length=32)
    default_allow: bool = False
    enforce: bool = False


class EnrollmentTokenCreate(BaseModel):
    label: str = ""
    max_uses: int | None = None       # None = unlimited
    expires_in_days: int | None = None


class EnrollRequest(BaseModel):
    token: str = Field(min_length=8, description="the enrollment token (et_…)")
    device: str = Field(min_length=1, description="device identity (used for the key label)")
    # Optional email-shaped identity (from SSO) to attribute findings to. Coverage
    # reconciliation matches on email-shaped actors, so when the enroller knows the user
    # (e.g. the extension after sign-in) pass it here; else attribution falls back to the
    # device string, which won't reconcile against the SSO/email shadow set. Validated to
    # a real email shape so it can't be a free-form label that spoofs another identity or
    # a wildcard that pollutes coverage/need-to-know matching.
    user: str = ""

    @field_validator("user")
    @classmethod
    def _validate_user(cls, v: str) -> str:
        return _email_shaped(v, required=False)


class ProvisionRequest(BaseModel):
    platform: Literal["macos", "windows", "linux", "both"] = "both"
    base_url: str = Field(min_length=1, description="public Palivane URL devices reach, e.g. https://palivane.corp")
    label: str = "device-provision"
    actor: str = ""               # per-user/device identity for attribution
    extension_id: str = ""        # published Chrome/Edge extension id (optional)
    proxy_host: str = ""          # host:port of the egress proxy (optional, desktop app)
    # Reroute Claude Code's API traffic through the Palivane gateway — bills the org's
    # provider key. Default off: Claude Code keeps its own sign-in (Pro/Max subscription
    # or API account) and managed-settings locks login to claude.ai (forceLoginMethod).
    route_gateway: bool = False
    # Bound lifetime for the fleet-wide enrollment token baked into the installer. It's a
    # reusable credential in a file, so it expires by default (override/disable explicitly).
    max_uses: int | None = None       # None = unlimited uses within the validity window
    expires_in_days: int | None = 30  # None = never expires (not recommended for a fleet file)


class AccessEvent(BaseModel):
    actor: str                    # user identity from the IdP/CASB record
    tool: str = ""                # AI tool/domain they accessed
    last_seen: str = ""           # ISO timestamp (optional)


class CoverageRequest(BaseModel):
    events: list[AccessEvent] = Field(min_length=1, max_length=20000)
    window_days: int | None = None  # only count findings within this many days as covered


class PolicyOverrideIn(BaseModel):
    scope: Literal["user", "group"]
    match: str = Field(min_length=1, max_length=320)   # email (user) or glob (group)
    channel: str = Field("", max_length=64)            # tool/channel glob ("" = any tool)
    label: str = Field("", max_length=128)
    disabled_checks: list[str] = Field(default_factory=list, max_length=64)
    # Staged enforcement: "on"/"off" force the matched actor/tool's stance,
    # "inherit" (default) leaves the tenant/global client_enforce in charge.
    enforce: Literal["on", "off", "inherit"] = "inherit"


class SimulateIn(BaseModel):
    """Console 'test my protection' — run content through the real scoring pipeline
    (nothing persisted) and show the verdict per plane, in monitor vs enforce."""
    content: str = Field(min_length=1, max_length=MAX_CONTENT)
    plane: Literal["prompt", "tool", "desktop", "browser"] = "prompt"
    actor: str = Field("", max_length=320)     # simulate as this user (override matching)
    tool: str = Field("", max_length=64)       # defaults per plane when empty
    destination: str = Field("", max_length=256)


class ExceptionResolve(BaseModel):
    """Admin decision on a queued exception request."""
    action: Literal["approve", "deny"]
    note: str = Field("", max_length=512)
    # approve only: checks to disable for the requester (defaults to the request's
    # categories ∩ the policy catalog) and the tool scope of the override ("" = any).
    disable_checks: list[str] = Field(default_factory=list, max_length=16)
    channel: str = Field("", max_length=64)


class AgentConfigScan(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENT)  # IDE/agent config blob
    user: str = ""                    # actor the config belongs to (per-user attribution)
    tool: str = "cursor"              # cursor | claude-code | aider | …
    record: bool = True


class AgentRulesScan(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENT)  # the rules-file contents
    user: str = ""                    # actor the file belongs to (per-user attribution)
    path: str = ""                    # e.g. "CLAUDE.md", ".cursor/rules/foo.mdc"
    tool: str = ""                    # claude-code | cursor | copilot | … (best-effort)
    record: bool = True


class OversharingScan(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENT)  # the LLM response returned
    # Recipient (the person who asked) — REQUIRED and email-shaped. This identity is the
    # need-to-know authorization input: the detector suppresses a finding only when the
    # recipient matches an allowed glob. It must be the SSO-authenticated end user the
    # integration served, not a free-form or omitted value — an unknown recipient must
    # never satisfy need-to-know (the endpoint fails closed).
    user: str = Field(min_length=3, description="recipient email (the person who asked)")
    source: str = ""                  # e.g. "m365-copilot", "glean", "internal-rag"
    record: bool = True

    @field_validator("user")
    @classmethod
    def _validate_user(cls, v: str) -> str:
        return _email_shaped(v, required=True)


class DiscoveryEvent(BaseModel):
    actor: str = ""                      # user identity from the log line
    destination: str = ""                # URL / domain seen (proxy, SWG, DNS)
    domain: str = ""                     # alias for destination
    tool: str = ""                       # or a named tool, if the log already resolved it
    team: str = ""                       # department/team, if the log carries it
    count: int = Field(1, ge=1, le=100000)  # events collapsed into this line (bounded)
    last_seen: str = ""                  # ISO timestamp (optional)


class OAuthGrant(BaseModel):
    """One third-party OAuth app a user granted access to a SaaS platform (Google Workspace,
    Microsoft 365, Slack, …). Where AI tools plug into SaaS via OAuth, they leave no network
    traffic a proxy/extension would see — this is the channel network capture misses."""
    app_name: str = ""                   # the OAuth app's display name
    app_id: str = ""                     # client id, if the export carries it
    user: str = ""                       # the granting user
    provider: str = ""                   # google | microsoft | slack | … (informational)
    scopes: list[str] = Field(default_factory=list, max_length=200)


class OAuthGrantIngest(BaseModel):
    grants: list[OAuthGrant] = Field(min_length=1, max_length=50000)


class ConnectorCreate(BaseModel):
    """A live-pull SaaS connector: platform key from saas_connectors.PLATFORMS plus the
    platform-specific credential fields (stored encrypted; never returned)."""
    platform: str
    label: str = Field("", max_length=128)
    credentials: dict = Field(default_factory=dict)


class DiscoveryIngest(BaseModel):
    events: list[DiscoveryEvent] = Field(min_length=1, max_length=50000)
