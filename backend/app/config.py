"""Runtime configuration, read from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass



def _env(name: str, default: str = "") -> str:
    """Read a PALIVANE_* env var, or `default`. (The legacy PALIVANE_* fallback was
    removed once prod migrated fully to the PALIVANE_ names — see the rebrand batches.)"""
    return os.getenv(name) or default


@dataclass
class Settings:
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    # OpenAI key for the LLM judge (also falls back to the gateway upstream key).
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    # LLM judge provider: "auto" picks whichever key is configured (anthropic > openai >
    # gemini); force one with "anthropic" | "openai" | "gemini", or "none" to disable.
    # "claude-cli" (judge via the signed-in Claude Code CLI on a subscription) is
    # DEPRECATED and will be removed: Anthropic's ToS (enforced 2026-04-04) restrict
    # subscription auth to Anthropic's own products — automated verdicts through the CLI
    # fall outside that. Still runs (explicit opt-in only, never via "auto") but logs a
    # deprecation warning; use an API key or per-tenant BYOK instead.
    judge_provider: str = os.getenv("JUDGE_PROVIDER", "auto")
    # Claude Code binary + per-verdict timeout for the DEPRECATED claude-cli provider.
    judge_cli_bin: str = os.getenv("JUDGE_CLI_BIN", "claude")
    judge_cli_timeout: float = float(os.getenv("JUDGE_CLI_TIMEOUT", "120"))
    # Model for the judgment call. Empty = a sensible per-provider default. Override for
    # cost/latency (e.g. claude-haiku-4-5, gpt-4o-mini, gemini-2.5-flash) via JUDGE_MODEL.
    judge_model: str = os.getenv("JUDGE_MODEL", "")
    # Claude via cloud contracts — for orgs WITHOUT an Anthropic API account (enterprise
    # subscription / marketplace procurement). JUDGE_PROVIDER=vertex bills the org's GCP
    # agreement (auth = Application Default Credentials — on Cloud Run/GKE the runtime
    # service account, no key material at all); JUDGE_PROVIDER=bedrock bills AWS (auth =
    # the standard credential chain). Both REQUIRE JUDGE_MODEL: cloud model ids are dated
    # per catalog (e.g. "claude-opus-4-8@20260115" on Vertex,
    # "us.anthropic.claude-opus-4-8-20260115-v1:0" on Bedrock), so there is no safe default.
    judge_vertex_project: str = os.getenv("JUDGE_VERTEX_PROJECT", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
    judge_vertex_region: str = os.getenv("JUDGE_VERTEX_REGION", "us-east5")
    judge_bedrock_region: str = os.getenv("JUDGE_BEDROCK_REGION", "us-east-1")
    # Per-call timeout for the API judge backends. Without it the provider SDK default
    # applies (anthropic: 10 MINUTES) — a hung provider call stalls the scan request far
    # past the egress proxy's scan budget and cascades into client-side fail-open.
    judge_timeout: float = float(os.getenv("JUDGE_TIMEOUT", "45"))
    # Active canary probe: exercise the judge every N seconds when real traffic hasn't,
    # so a dead provider (revoked key, exhausted credits, outage) pages the operator
    # BEFORE the first real scan degrades. 0 disables. The canary uses a minimal prompt,
    # not the full analyst prompt, so each probe costs a few tokens.
    judge_probe_interval: float = float(os.getenv("JUDGE_PROBE_INTERVAL", "900"))
    # Whether the LLM judge is a plan-gated entitlement. On the managed SaaS the judge key
    # is operator-funded, so it is bundled only into the paid tier(s) that carry the "judge"
    # feature (see app/plans.py). Self-hosted leaves this off (default): the operator sets
    # their own provider key and the judge runs for everyone whenever a key is configured.
    judge_plan_gated: bool = _env("PALIVANE_JUDGE_PLAN_GATED", "").lower() in ("1", "true", "yes")
    # Raw event archival to the tenant's S3 sink (archive_s3.py): NDJSON micro-batch flush
    # thresholds, and the default per-tenant daily byte budget (MB; a tenant column > 0
    # overrides). Events go to AWS from GCP — internet egress — so the cap is a cost guard.
    archive_flush_kb: int = int(_env("PALIVANE_ARCHIVE_FLUSH_KB", "64"))
    archive_flush_secs: int = int(_env("PALIVANE_ARCHIVE_FLUSH_SECS", "5"))
    archive_daily_mb: int = int(_env("PALIVANE_ARCHIVE_DAILY_MB", "512"))
    # Session behavioral correlation: after a finding is stored, look across the actor's
    # recent activity for an escalating attack CHAIN (recon → collection → exfil) that no
    # single event trips. On by default; window is how far back to look (minutes).
    session_correlation: bool = _env("PALIVANE_SESSION_CORRELATION", "true").lower() in ("1", "true", "yes")
    session_window_min: int = int(_env("PALIVANE_SESSION_WINDOW_MIN", "30"))
    # MCP server reputation/provenance (beyond allowlist + TOFU pinning): a known-bad
    # denylist (server names or packages, comma-separated), and an opt-in registry
    # freshness check that flags freshly-published / freshly-republished packages — the
    # postmark-mcp "trusted then trojaned" tell. Registry lookups are off by default
    # (network egress) and always fail open.
    mcp_server_denylist: str = os.getenv("MCP_SERVER_DENYLIST", "")
    mcp_reputation_enabled: bool = os.getenv("MCP_REPUTATION_ENABLED", "").lower() in ("1", "true", "yes")
    mcp_reputation_fresh_days: int = int(os.getenv("MCP_REPUTATION_FRESH_DAYS", "14"))
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./warden.db")
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    # Reject request bodies larger than this (DoS/OOM guard); ~12 MB default.
    max_body_bytes: int = int(_env("PALIVANE_MAX_BODY_BYTES", "12000000"))
    # Auth. Set PALIVANE_SECRET_KEY in production (signs JWTs). Empty => an insecure
    # dev fallback is used and the API logs a warning at startup.
    auth_secret_key: str = _env("PALIVANE_SECRET_KEY", "")
    auth_token_ttl: int = int(os.getenv("AUTH_TOKEN_TTL", "43200"))  # seconds (12h)
    # Brute-force protection: after this many failed logins for an email within the
    # window (seconds), further attempts are refused (HTTP 429) until it elapses.
    login_max_fails: int = int(_env("PALIVANE_LOGIN_MAX_FAILS", "5"))
    # A single IP hammering many emails is blocked at a higher threshold (a shared office
    # NAT has several legit users, so it's looser than the per-email limit).
    login_ip_max_fails: int = int(_env("PALIVANE_LOGIN_IP_MAX_FAILS", "20"))
    login_window: int = int(_env("PALIVANE_LOGIN_WINDOW", "300"))
    # Redact secrets/PII from stored finding content so Palivane's own DB isn't a
    # plaintext-secret honeypot. Detection still runs on the raw content.
    redact_findings: bool = _env("PALIVANE_REDACT_FINDINGS", "true").lower() in ("1", "true", "yes")
    # Encrypt stored finding content at rest (decrypted on read for authorized admins).
    # Opt-in: requires a durable PALIVANE_ENCRYPTION_KEY/PALIVANE_SECRET_KEY (key loss = data loss).
    encrypt_findings: bool = _env("PALIVANE_ENCRYPT_FINDINGS", "").lower() in ("1", "true", "yes")
    # Persist the raw prompt PROSE in findings? Default OFF: store the verdict, signal
    # categories, redacted evidence, and attribution — but not the natural-language content,
    # which can't be redacted for concepts/IP and would make the store a honeypot. A tenant
    # can opt in (store_content column) for richer triage of its own data.
    store_content: bool = _env("PALIVANE_STORE_CONTENT", "").lower() in ("1", "true", "yes")
    # For tenants that DO store content, scrub it (keep metadata) after this many days.
    # Bounds the exposure window instead of keeping prose forever. 0 = never scrub.
    content_ttl_days: int = int(_env("PALIVANE_CONTENT_TTL_DAYS", "30"))
    # Self-serve signup: anyone can create a new org (tenant). Set false on a
    # single-org self-hosted deployment to lock it down after bootstrapping.
    allow_signup: bool = _env("PALIVANE_ALLOW_SIGNUP", "true").lower() in ("1", "true", "yes")
    # Current data-processing-agreement version an org accepts (compliance record). Bump
    # when the DPA text changes to prompt re-acceptance.
    dpa_version: str = _env("PALIVANE_DPA_VERSION", "1.0")
    # Public origin of this deployment (e.g. https://app.palivane.io). When set, SSO builds
    # its token-bearing redirect from THIS, not the client Host header — closing a
    # host-header open-redirect / session-token exfil. Also seeds the trusted-host allowlist.
    public_base_url: str = _env("PALIVANE_PUBLIC_URL", "").rstrip("/")
    # Build identity, surfaced to clients so they can tell whether their installed copies
    # of the hooks/proxy addon are current (see /cli/manifest.json). The deploy sets it to
    # the image tag; "dev" locally. Clients compare FILE HASHES from the manifest, not this
    # string — it's for display, fleet inventory, and staging an update.
    version: str = _env("PALIVANE_VERSION", "dev")
    # Hosted signups start a full-featured trial of this many days; 0 puts new orgs on the
    # free (self-host equivalent) tier instead — set that for a self-hosted deployment where
    # every org is local and there is nothing to sell.
    trial_days: int = int(_env("PALIVANE_TRIAL_DAYS", "14"))
    # Refuse to serve self-updates (clients keep whatever they have). For fleets that
    # manage the scripts via MDM and don't want devices pulling their own updates.
    self_update_enabled: bool = _env("PALIVANE_SELF_UPDATE", "true").lower() in ("1", "true", "yes")
    # Comma-separated Host allowlist for TrustedHostMiddleware (empty = disabled).
    allowed_hosts: str = _env("PALIVANE_ALLOWED_HOSTS", "")
    # Tenant that capture clients (extension/proxy) attribute findings to (slug or id).
    ingest_tenant: str = os.getenv("INGEST_TENANT", "")
    # Default gateway requests-per-minute limit per tenant (0 = unlimited). A tenant's own
    # rate_limit overrides this. Enforced as a fixed 60s window; also the metering source.
    gateway_rate_limit: int = int(os.getenv("GATEWAY_RATE_LIMIT", "0"))
    # Default sensor/ingest req/min per tenant (capture planes: /api/ingest/*, /api/scan/*),
    # counted separately from the gateway so agentic volume can't starve LLM traffic
    # (0 = unlimited). A tenant's own ingest_rate_limit overrides this.
    ingest_rate_limit: int = int(os.getenv("INGEST_RATE_LIMIT", "0"))
    # Outbound email (password reset, join verification, invites). Dark until SMTP_HOST +
    # MAIL_FROM are set; flows degrade to email-less behavior. Provider-neutral SMTP.
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_pass: str = os.getenv("SMTP_PASS", "")
    smtp_tls: bool = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes")
    mail_from: str = os.getenv("MAIL_FROM", "")
    # Per-tenant resource quotas for open multi-tenant signup (0 = unlimited). A tenant's
    # own quota_* column (operator-set via `python -m app.users set-quota`) overrides the
    # global default — tenant admins can NOT raise their own quotas through the API.
    quota_users: int = int(_env("PALIVANE_QUOTA_USERS", "25"))
    quota_api_keys: int = int(_env("PALIVANE_QUOTA_API_KEYS", "100"))
    quota_ingest_per_day: int = int(_env("PALIVANE_QUOTA_INGEST_PER_DAY", "50000"))
    # Persist benign MCP-surface findings (palivane-hook/palivane-mcp tool calls)? Default off:
    # the vast majority of tool calls are benign noise; only warn+ verdicts are stored.
    mcp_persist_benign: bool = _env("PALIVANE_MCP_PERSIST_BENIGN", "").lower() in ("1", "true", "yes")
    # Persist benign usage-capture findings (ai-usage ingest / OTLP prompts, gateway prompt
    # capture + response DLP)? Default off — benign traffic is volume, not findings; the
    # discovery inventory and usage counters are fed independently of persistence. Turn on
    # for a full per-event egress audit trail.
    usage_persist_benign: bool = _env("PALIVANE_USAGE_PERSIST_BENIGN", "").lower() in ("1", "true", "yes")
    # If set, /metrics requires this token (Bearer or ?token=); empty = open (bind it to
    # an internal network / scrape it privately). Stripped: secret-manager values often
    # carry a trailing newline (echo | secrets create), which no pasted token can match.
    # Do NOT strip PALIVANE_SECRET_KEY — its exact bytes are baked into every session
    # signature and the encryption-key derivation.
    metrics_token: str = _env("PALIVANE_METRICS_TOKEN", "").strip()
    # Operator (instance-level) alert webhook — Slack-compatible. Currently used to page when
    # the LLM judge goes down (all providers erroring, e.g. exhausted API credits). Distinct
    # from per-tenant alert_webhook; empty = log/health only.
    ops_webhook: str = _env("PALIVANE_OPS_WEBHOOK", "").strip()
    # Where in-console upgrade requests and trial emails point buyers. One knob so a
    # self-hosted reseller (or a future address change) doesn't chase hardcoded strings.
    sales_email: str = _env("PALIVANE_SALES_EMAIL", "sales@tachtech.net").strip()

    # --- LLM gateway (protect our AI) ---
    # enforce=block risky prompts; otherwise monitor (observe + record only). Block when
    # verdict severity >= block_severity.
    gateway_enforce: bool = os.getenv("GATEWAY_ENFORCE", "").lower() in ("1", "true", "yes")
    # Even in monitor mode, hard-block a CONFIRMED secret/PII leak (known-format credential
    # or PII) heading to an AI tool — near-zero false positives, high cost of a miss. This is
    # the "block the certain, monitor the fuzzy" default; set false to monitor those too.
    gateway_enforce_secrets: bool = os.getenv("GATEWAY_ENFORCE_SECRETS", "true").lower() in ("1", "true", "yes")
    gateway_block_severity: str = os.getenv("GATEWAY_BLOCK_SEVERITY", "high")
    # Local capture planes (CLI hooks + desktop egress proxy): default enforce stance,
    # returned to clients in ingest verdicts (tenants override per-org in Settings).
    # false = monitor — confirmed secret/PII leaks still hard-block via force_block.
    client_enforce: bool = os.getenv("CLIENT_ENFORCE", "").lower() in ("1", "true", "yes")
    # Response-side DLP: scan the model's OUTPUT for secrets/PII (records; blocks in enforce).
    gateway_scan_responses: bool = os.getenv("GATEWAY_SCAN_RESPONSES", "true").lower() in ("1", "true", "yes")
    # Opt-in OCR of images sent to LLMs (screenshots carry secrets/PII the text scan never
    # sees). Requires pytesseract + Pillow AND the tesseract binary; default off. When
    # enabled, OCR text is appended to the scanned content for detection only — it is
    # never stored beyond normal finding evidence.
    gateway_ocr: bool = _env("PALIVANE_OCR", "").lower() in ("1", "true", "yes")
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
    # Stripped like metrics_token: a trailing newline from secret tooling must not break
    # header comparison.
    extension_ingest_token: str = os.getenv("EXTENSION_INGEST_TOKEN", "").strip()
    # AI tools/domains the org has approved — a matching destination is not flagged.
    # Comma-separated, e.g. "claude.ai,copilot.microsoft.com". Empty = all unsanctioned.
    sanctioned_ai_tools: str = os.getenv("SANCTIONED_AI_TOOLS", "")
    # Per-tool category suppression, e.g. "claude-code:source_code_leak;cursor:source_code_leak".
    gateway_tool_suppress: str = os.getenv("GATEWAY_TOOL_SUPPRESS", "")
    # Published Chrome/Edge extension id — set once the extension is on the store so
    # generated installers write the browser managed policy under the right id.
    # The published (Unlisted) Chrome/Edge extension id — the single source of truth for it.
    # Feeds the CORS allowlist (so the extension can reach the backend), the MDM force-install
    # policy, and the device installers. Override per deployment with a self-hosted CRX id.
    extension_id: str = _env("PALIVANE_EXTENSION_ID", "hoikdfmlhoakggmofeapanfnnbmoaghh")

    # --- MCP inspection (agentic tool-use, via the egress proxy) ---
    # enforce=block risky MCP calls; otherwise monitor. Block when severity >= block_severity.
    mcp_enforce: bool = os.getenv("MCP_ENFORCE", "").lower() in ("1", "true", "yes")
    mcp_block_severity: str = os.getenv("MCP_BLOCK_SEVERITY", "high")
    # CI-runner scans block only on `critical` by default (confirmed exposure). Posture
    # findings — unpinned actions, write-all, self-hosted runners — warn: they are usually
    # pre-existing debt, and a PR gate that fails on debt the author didn't add gets deleted.
    ci_block_severity: str = os.getenv("CI_BLOCK_SEVERITY", "critical")
    # Allowlist of approved (inspectable, remote) MCP server hosts — comma-separated, e.g.
    # "mcp.githubcopilot.com,mcp.acme.com". Empty = don't flag on server identity. A call to
    # a server not on a non-empty list is flagged (policy-flag stance for shadow MCP).
    mcp_allowed_servers: str = os.getenv("MCP_ALLOWED_SERVERS", "")
    # Extra known-bad dependency names to flag in manifests (comma-separated), merged with
    # a small built-in denylist.
    dep_denylist: str = os.getenv("DEP_DENYLIST", "")
    # Opt-in CVE/advisory lookup for pinned dependencies via the OSV.dev batch API. Makes an
    # outbound call at scan time (agentless / CI-shaped); fails open if unreachable.
    dep_osv_enabled: bool = os.getenv("DEP_OSV_ENABLED", "").lower() in ("1", "true", "yes")
    dep_osv_url: str = os.getenv("DEP_OSV_URL", "https://api.osv.dev/v1/querybatch")
    # IDE-extension vetting: known-bad extension ids (comma-separated) merged with a small
    # built-in denylist, and an optional approved-extension allowlist (empty = allow all).
    ide_ext_denylist: str = os.getenv("IDE_EXT_DENYLIST", "")
    ide_ext_allowed: str = os.getenv("IDE_EXT_ALLOWED", "")


settings = Settings()
