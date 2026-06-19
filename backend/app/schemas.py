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


class StatusUpdate(BaseModel):
    status: Literal["open", "triaged", "dismissed"]


# --- auth / tenancy ---

class LoginRequest(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=1)


class SignupRequest(BaseModel):
    org_name: str = Field(min_length=2, description="organization / tenant name")
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
    slug: str = ""   # optional; derived from org_name when blank


class UserCreate(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
    role: Literal["admin", "analyst"] = "analyst"


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
