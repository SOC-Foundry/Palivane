"""Runtime configuration, read from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    # Default to the most capable model for the judgment call. For high-volume
    # production triage you may switch to claude-haiku-4-5 or claude-sonnet-4-6
    # to trade some accuracy for cost/latency — set JUDGE_MODEL to override.
    judge_model: str = os.getenv("JUDGE_MODEL", "claude-opus-4-8")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./warden.db")
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    # Auth. Set WARDEN_SECRET_KEY in production (signs JWTs). Empty => an insecure
    # dev fallback is used and the API logs a warning at startup.
    auth_secret_key: str = os.getenv("WARDEN_SECRET_KEY", "")
    auth_token_ttl: int = int(os.getenv("AUTH_TOKEN_TTL", "43200"))  # seconds (12h)
    # Self-serve signup: anyone can create a new org (tenant). Set false on a
    # single-org self-hosted deployment to lock it down after bootstrapping.
    allow_signup: bool = os.getenv("WARDEN_ALLOW_SIGNUP", "true").lower() in ("1", "true", "yes")
    # Tenant that capture clients (extension/proxy) attribute findings to (slug or id).
    ingest_tenant: str = os.getenv("INGEST_TENANT", "")

    # --- LLM gateway (protect our AI) ---
    # enforce=block risky prompts; otherwise monitor (observe + record only). Block when
    # verdict severity >= block_severity.
    gateway_enforce: bool = os.getenv("GATEWAY_ENFORCE", "").lower() in ("1", "true", "yes")
    gateway_block_severity: str = os.getenv("GATEWAY_BLOCK_SEVERITY", "high")
    # OpenAI-compatible upstream for /v1/chat/completions (empty = stub reply offline).
    gateway_upstream_base: str = os.getenv("GATEWAY_UPSTREAM_BASE", "")
    gateway_upstream_key: str = os.getenv("GATEWAY_UPSTREAM_KEY", "")
    # Anthropic Messages upstream for /v1/messages (e.g. Claude Code). Key falls back
    # to ANTHROPIC_API_KEY. Empty key = stub reply (offline-demoable).
    gateway_anthropic_base: str = os.getenv("GATEWAY_ANTHROPIC_BASE", "https://api.anthropic.com")
    gateway_anthropic_key: str = os.getenv("GATEWAY_ANTHROPIC_KEY", "")
    # Gemini generateContent upstream for /v1beta/models/{model}:generateContent
    # (google-genai SDK, Gemini CLI). Key falls back to GEMINI_API_KEY. Empty = stub.
    gateway_gemini_base: str = os.getenv("GATEWAY_GEMINI_BASE", "https://generativelanguage.googleapis.com")
    gateway_gemini_key: str = os.getenv("GATEWAY_GEMINI_KEY", "")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")

    # --- Shadow-AI governance ---
    # Static token the browser extension / egress proxy present on /api/ingest/ai-usage.
    extension_ingest_token: str = os.getenv("EXTENSION_INGEST_TOKEN", "")
    # AI tools/domains the org has approved — a matching destination is not flagged.
    # Comma-separated, e.g. "claude.ai,copilot.microsoft.com". Empty = all unsanctioned.
    sanctioned_ai_tools: str = os.getenv("SANCTIONED_AI_TOOLS", "")
    # Per-tool category suppression, e.g. "claude-code:source_code_leak;cursor:source_code_leak".
    gateway_tool_suppress: str = os.getenv("GATEWAY_TOOL_SUPPRESS", "")


settings = Settings()
