"""API request/response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Surface = Literal["llm_io", "ai_usage"]


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, description="content to analyze")
    subject: str = ""            # optional label
    # 'llm_io' = prompts/responses on our own LLMs; 'ai_usage' = content bound for an AI tool.
    surface: Surface = "llm_io"
    destination: str = ""        # where the content is being sent (AI tool name or URL)
    persist: bool = True


class BatchAnalyzeRequest(BaseModel):
    items: list[AnalyzeRequest] = Field(min_length=1, max_length=500)


class AIUsageIngest(BaseModel):
    """Content a browser extension or proxy captured on its way to an external AI tool."""
    content: str = Field(min_length=1)
    destination: str = ""   # AI tool URL/domain
    user: str = ""          # end-user identity (from SSO/extension)
    tool: str = ""          # capturing tool id (e.g. "claude-code") for per-tool policy


class MCPIngest(BaseModel):
    """A normalized MCP JSON-RPC activity the egress proxy captured (agentic tool-use)."""
    method: str = ""                                   # tools/call, resources/read, initialize, tools/list.result
    server: str = ""                                   # MCP server host
    tool: str = ""                                     # tool name for tools/call
    args_text: str = ""                                # joined string values of the tool arguments
    resource: str = ""                                 # URI/path for resources/read
    tool_descriptions: list[str] = Field(default_factory=list)  # for tools/list.result / advertised tools
    transport: str = "http"                            # http | stdio | via-llm-api
    user: str = ""                                     # end-user identity


class MCPConfigScan(BaseModel):
    """An MCP configuration file (.mcp.json, Cursor/VS Code) to vet in CI or the console."""
    content: str = Field(min_length=1)
    path: str = ""
    record: bool = False   # persist non-clean servers as findings (off by default)


class IDEExtScan(BaseModel):
    """IDE extensions to vet — a list of ids, or a `.vscode/extensions.json` file content."""
    extensions: list[str] = Field(default_factory=list)
    content: str = ""       # e.g. .vscode/extensions.json (recommendations)
    record: bool = False


class CodeFile(BaseModel):
    path: str = ""
    content: str


class CodeScanRequest(BaseModel):
    # A pre-commit hook / CI step sends the changed files; we scan each for secrets & PII.
    files: list[CodeFile] = Field(default_factory=list)
    record: bool = False          # persist non-clean files as findings (off by default)


class StatusUpdate(BaseModel):
    status: Literal["open", "triaged", "dismissed"]


# --- auth / tenancy ---

class LoginRequest(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=1)
    # Optional tenant (org slug). Required only to disambiguate an email that exists in
    # more than one org (multi-tenant hosting); single-tenant/demo login omits it.
    org: str = ""


class SignupRequest(BaseModel):
    org_name: str = Field(min_length=2, description="organization / tenant name")
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
    slug: str = ""   # optional; derived from org_name when blank


class UserCreate(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
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
    rate_limit: int | None = None       # gateway requests/min (0 = inherit global default)
    mcp_allowed_servers: str | None = None  # comma-separated approved MCP server hosts
    ide_ext_allowed: str | None = None      # approved IDE extension ids
    ide_ext_denylist: str | None = None     # blocked IDE extension ids
    dep_denylist: str | None = None         # known-bad dependency names
    alert_webhook: str | None = None        # Slack-compatible webhook for high/critical alerts
    alert_min_severity: str | None = None   # minimum severity to alert on


class TenantDelete(BaseModel):
    confirm: str = ""   # must equal the tenant slug — guards against accidental deletion


class UpstreamConfig(BaseModel):
    base_url: str = ""
    # Write-only: the provider API key. Stored encrypted, never returned. Leave empty on
    # an update to keep the existing key (e.g. when only changing base_url).
    key: str = ""


class ApiKeyCreate(BaseModel):
    label: str = ""
    actor: str = ""               # identity to attribute this key's traffic to
    expires_in_days: int | None = None


class EnrollmentTokenCreate(BaseModel):
    label: str = ""
    max_uses: int | None = None       # None = unlimited
    expires_in_days: int | None = None


class EnrollRequest(BaseModel):
    token: str = Field(min_length=8, description="the enrollment token (et_…)")
    device: str = Field(min_length=1, description="device / user identity for attribution")


class ProvisionRequest(BaseModel):
    platform: Literal["macos", "windows", "both"] = "both"
    base_url: str = Field(min_length=1, description="public Warden URL devices reach, e.g. https://warden.corp")
    label: str = "device-provision"
    actor: str = ""               # per-user/device identity for attribution
    extension_id: str = ""        # published Chrome/Edge extension id (optional)
    proxy_host: str = ""          # host:port of the egress proxy (optional, desktop app)


class AccessEvent(BaseModel):
    actor: str                    # user identity from the IdP/CASB record
    tool: str = ""                # AI tool/domain they accessed
    last_seen: str = ""           # ISO timestamp (optional)


class CoverageRequest(BaseModel):
    events: list[AccessEvent] = Field(min_length=1, max_length=20000)
    window_days: int | None = None  # only count findings within this many days as covered
