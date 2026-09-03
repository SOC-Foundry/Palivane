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
    # Palivane's own AWS principal (IAM user/role ARN) that customer-side delivery roles
    # trust for role-based S3 delivery (STS AssumeRole). Operator-level: it names THIS
    # deployment's AWS identity, and the console's role-setup helper embeds it in the
    # trust policy it hands tenant admins. Empty = role delivery is not offered at all
    # (see role_delivery_principal below), not offered with a placeholder.
    aws_delivery_principal: str = _env("PALIVANE_AWS_DELIVERY_PRINCIPAL", "").strip()
    # GCP→AWS web-identity federation (aws_wif.py): the AWS role this runtime assumes
    # with its GCP identity token — the no-stored-secret alternative to static AWS env
    # keys for a GCP-hosted deployment. Empty = fall back to boto3's default chain.
    # The audience must match the accounts.google.com:oaud condition in that role's
    # trust policy (and is otherwise arbitrary).
    aws_wif_role_arn: str = _env("PALIVANE_AWS_WIF_ROLE_ARN", "").strip()
    aws_wif_audience: str = _env("PALIVANE_AWS_WIF_AUDIENCE", "palivane-aws-delivery").strip()
    # The published "Palivane" Slack app (operator registers ONE app at api.slack.com):
    # client id/secret drive the per-tenant "Add to Slack" OAuth install flow, which
    # stores each workspace's bot token as a slack_messages connector. Empty = the
    # install flow is off; tenants can still paste a hand-built app's bot token.
    # redirect_url overrides the auto-derived callback (set it when a proxy rewrites
    # the scheme/host the app sees).
    slack_client_id: str = _env("PALIVANE_SLACK_CLIENT_ID", "").strip()
    slack_client_secret: str = _env("PALIVANE_SLACK_CLIENT_SECRET", "").strip()
    slack_redirect_url: str = _env("PALIVANE_SLACK_REDIRECT_URL", "").strip()
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
    # Path to a scored MCP-server reputation feed (JSON: name -> {tier, score, reason}).
    # Empty = feed disabled (denylist + provenance + freshness still run). The feed itself
    # — e.g. a curated/licensed dataset seeded from the official MCP registry — is an
    # out-of-band data artifact the operator points this at; the code is the consumer.
    mcp_reputation_feed: str = os.getenv("MCP_REPUTATION_FEED", "").strip()
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./palivane.db")
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
    # Coaching mode: turn a redactable data-loss BLOCK into a WARN that shows the cleaned
    # version + a sanctioned-tool redirect, instead of a hard stop. Off by default (blocking
    # is the safe default); a tenant opts in. Named "redact" because the coaching UI surfaces
    # the redacted prompt the user can send instead.
    redact_mode: bool = _env("PALIVANE_REDACT_MODE", "").lower() in ("1", "true", "yes")
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
    # UNLABELED ml-corpus samples (consented capture, see ml/capture.py) are deleted on
    # the same clock — prose nobody triaged is exposure, not data. Labeled rows are kept.
    content_ttl_days: int = int(_env("PALIVANE_CONTENT_TTL_DAYS", "30"))
    # Consented ML-corpus capture, for tenants that set ml_capture=true (off by default):
    # sample this percent of scanned gateway prompts into the labeling queue, capped per
    # tenant per UTC day. Both bound volume, not consent — consent is the tenant flag.
    ml_capture_sample_pct: int = int(_env("PALIVANE_ML_CAPTURE_PCT", "10"))
    ml_capture_max_per_day: int = int(_env("PALIVANE_ML_CAPTURE_MAX_PER_DAY", "200"))
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
    # Issuer bound into session JWTs (`iss`). Defaults to the public URL so tokens minted by
    # one deployment don't verify on another that happens to share the signing key. Enforced
    # only when a token actually carries `iss`, so pre-existing tokens keep working until they
    # expire (no forced logout on rollout). Empty = don't set or check `iss`.
    jwt_iss: str = _env("PALIVANE_JWT_ISS", "") or _env("PALIVANE_PUBLIC_URL", "").rstrip("/")
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
    # Defaults to a generous non-zero ceiling so a single leaked/abused key can't drive
    # unbounded upstream spend; raise per-tenant (Tenant.rate_limit) for high-volume orgs.
    gateway_rate_limit: int = int(os.getenv("GATEWAY_RATE_LIMIT", "600"))
    # Per-tenant daily gateway request cap (0 = unlimited). The minute limit stops bursts;
    # this backstops sustained cost-amplification over a day (ingest already has its own).
    quota_gateway_per_day: int = int(_env("PALIVANE_QUOTA_GATEWAY_PER_DAY", "200000"))
    # Hard ceiling on the output-token count forwarded upstream, whatever the client asks
    # for. Caps the cost of any single proxied call (0 = don't clamp). Applies to OpenAI
    # max_tokens / max_output_tokens, Anthropic max_tokens, and Gemini maxOutputTokens.
    gateway_max_output_tokens: int = int(_env("PALIVANE_GATEWAY_MAX_OUTPUT_TOKENS", "16384"))
    # Default sensor/ingest req/min per tenant (capture planes: /api/ingest/*, /api/scan/*),
    # counted separately from the gateway so agentic volume can't starve LLM traffic
    # (0 = unlimited). A tenant's own ingest_rate_limit overrides this.
    ingest_rate_limit: int = int(os.getenv("INGEST_RATE_LIMIT", "0"))
    # Outbound email (password reset, join verification, invites). Dark until MAIL_FROM
    # plus a delivery path are set; flows degrade to email-less behavior. Two paths:
    # provider-neutral SMTP, or the Cloudflare Email Service REST API (no SMTP relay
    # needed — the sender domain is onboarded once in the Cloudflare dashboard). When
    # both are configured, SMTP wins: an explicitly pointed relay beats the platform API.
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_pass: str = os.getenv("SMTP_PASS", "")
    smtp_tls: bool = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes")
    mail_from: str = os.getenv("MAIL_FROM", "")
    # Cloudflare Email Service: the account id is not a secret; the API token (needs the
    # Email Sending permission) is — in cloud deploys it rides in from Secret Manager
    # (palivane-cf-email-token), same as the other provider keys.
    cf_email_account_id: str = _env("CF_EMAIL_ACCOUNT_ID", "").strip()
    cf_email_token: str = _env("CF_EMAIL_TOKEN", "").strip()
    # Azure OpenAI (rides the "openai" upstream slot — paste the resource URL as the
    # base; see gateway._openai_upstream): the api-version used for the classic
    # deployments URL layout. The 2025+ /openai/v1 unified endpoint ignores it.
    gateway_azure_api_version: str = _env("GATEWAY_AZURE_API_VERSION", "2024-10-21")
    # Public read-only demo (see app/demo.py): slug of the tenant the demo button signs
    # into (seed it with `python -m app.seed`). Empty = no demo. Demo sessions carry a
    # `demo` claim that get_current_user enforces as read-only.
    demo_org: str = _env("PALIVANE_DEMO_ORG", "").strip().lower()
    # "Continue with Google" (app-global social sign-in; see app/google_login.py) — one
    # OAuth client for the whole deployment, distinct from per-tenant OIDC SSO. Dark
    # until both are set. The secret rides in from Secret Manager
    # (palivane-google-oauth-secret); the client id is not a secret.
    google_oauth_client_id: str = _env("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    google_oauth_client_secret: str = _env("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    # Self-serve billing (Stripe Checkout for the Team plan; Enterprise stays sales-led).
    # Dark until the secret key + at least one price id are set (see app/billing.py).
    # Secrets ride in from Secret Manager (palivane-stripe-secret-key / -webhook-secret);
    # price ids are not secrets.
    stripe_secret_key: str = _env("STRIPE_SECRET_KEY", "").strip()
    stripe_webhook_secret: str = _env("STRIPE_WEBHOOK_SECRET", "").strip()
    # Publishable key (pk_…) — NOT a secret; the frontend mounts embedded Checkout with it.
    stripe_publishable_key: str = _env("STRIPE_PUBLISHABLE_KEY", "").strip()
    stripe_price_team_monthly: str = _env("STRIPE_PRICE_TEAM_MONTHLY", "").strip()
    stripe_price_team_annual: str = _env("STRIPE_PRICE_TEAM_ANNUAL", "").strip()
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
    sales_email: str = _env("PALIVANE_SALES_EMAIL", "sales@palivane.io").strip()

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
    # Tokenize personal data in gateway traffic: substitute a placeholder on the way to the
    # provider and put the real value back in the answer, so the model can reason over a
    # record's structure without OpenAI/Anthropic ever holding its contents. Off by default
    # because it changes what the provider receives, which is a deliberate decision rather
    # than a default. The map lives in the request handler and is never stored. Scoring runs
    # on the ORIGINAL text, before substitution, so detection is unaffected either way.
    gateway_tokenize: bool = _env("GATEWAY_TOKENIZE", "").lower() in ("1", "true", "yes")
    # Opt-in OCR of images sent to LLMs (screenshots carry secrets/PII the text scan never
    # sees). Requires pytesseract + Pillow AND the tesseract binary; default off. When
    # enabled, OCR text is appended to the scanned content for detection only — it is
    # never stored beyond normal finding evidence.
    gateway_ocr: bool = _env("PALIVANE_OCR", "").lower() in ("1", "true", "yes")
    # Path to the confidential-content classifier's weights (app/ml/confidential.py). Empty
    # or missing = the model contributes nothing, which is the default: no weights ship in
    # the repo, because a model trained on synthetic data has no business in a live path.
    ml_confidential_model: str = _env("PALIVANE_ML_CONFIDENTIAL_MODEL", "").strip()
    # The Enterprise tier of the same classifier: a fine-tuned encoder run through ONNX
    # Runtime on CPU, locally (app/ml/encoder.py). Both paths empty = the linear model is
    # the only classifier, which is the default. Needs onnxruntime + tokenizers installed;
    # the deploy image does not carry them, so this is opt-in twice over.
    ml_encoder_model: str = _env("PALIVANE_ML_ENCODER_MODEL", "").strip()
    ml_encoder_tokenizer: str = _env("PALIVANE_ML_ENCODER_TOKENIZER", "").strip()
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
    # The published Chrome/Edge extension id. Deliberately EMPTY by default.
    #
    # A Web Store id belongs to the developer account that published the item, not to this
    # code, so the previous default was an id owned by a company that no longer ships this
    # product. Shipping it as a default is not merely stale: it lands in the CORS allowlist
    # and, worse, in the MDM ExtensionInstallForcelist, which would force-install a
    # third-party extension onto every managed device in a customer's fleet.
    #
    # Unset is handled everywhere: main.py appends the CORS origin only when this is set,
    # and policy_pack emits REPLACE_WITH_PALIVANE_EXTENSION_ID so an admin sees what to
    # fill in. Set PALIVANE_EXTENSION_ID once the item is published, or to a self-hosted
    # CRX id derived from your own signing key.
    extension_id: str = _env("PALIVANE_EXTENSION_ID", "")

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

    @property
    def role_delivery_principal(self) -> str:
        """The AWS identity a customer's trust policy must name for role-based S3
        delivery to work: the static principal if the operator set one, otherwise the
        GCP-federated role this runtime assumes (aws_wif). Empty means this deployment
        has no AWS identity at all, so no AssumeRole against a customer role can ever
        succeed and role delivery must not be offered, configured, or counted as set up."""
        return self.aws_delivery_principal or self.aws_wif_role_arn


settings = Settings()
