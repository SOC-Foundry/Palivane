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


class TenantUpdate(BaseModel):
    name: str | None = None
    # Claude judge for this org: "on"/"off" force it; "inherit" follows the global key.
    # None (field omitted) = leave unchanged.
    judge: Literal["on", "off", "inherit"] | None = None
    retention_days: int | None = None   # 0 = keep findings forever


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


class AccessEvent(BaseModel):
    actor: str                    # user identity from the IdP/CASB record
    tool: str = ""                # AI tool/domain they accessed
    last_seen: str = ""           # ISO timestamp (optional)


class CoverageRequest(BaseModel):
    events: list[AccessEvent] = Field(min_length=1, max_length=20000)
    window_days: int | None = None  # only count findings within this many days as covered
