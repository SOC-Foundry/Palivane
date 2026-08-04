# Warden — Overview

**Govern how your organization uses AI. DETECT · BLOCK · PROTECT.**

Warden is a **hosted, multi-tenant** security gateway for AI (self-hostable if you prefer).
It sits between the people and tools in your organization and the large language models they
talk to — whether that's your own LLM applications or public services like ChatGPT, Claude,
and Gemini — and it detects, records, and (optionally) blocks risky prompts and data before
they cause harm. As a customer you don't run infrastructure: you sign in to your console and
configure every capture plane from **Connect → Quick start**.

---

## 1. The problem Warden solves

Organizations adopting AI face two distinct risks at the same time:

**Front 1 — Attacks on your own LLM applications.**
If you run an AI feature, users (or attackers) will try to subvert it: prompt
injection, jailbreaks, guardrail evasion, and attempts to exfiltrate your system prompt,
API keys, or other secrets the model can see.

**Front 2 — Shadow-AI data leakage.**
Employees paste secrets (API keys, AWS credentials, tokens), PII (SSNs, credit cards,
contact lists), and proprietary source code into public AI tools — often through
unsanctioned apps that IT never approved.

Warden addresses both fronts from one control plane. Crucially, it captures this traffic
**automatically at the edge** rather than relying on manual review, and it can run in
**monitor mode** (record and alert) or **enforce mode** (block inline).

---

## 2. What Warden does

- **Detects** prompt-injection / jailbreak / exfiltration attacks against your LLMs.
- **Detects** secrets, PII, and source code leaving your org toward external AI tools —
  including keys whose separator was stripped to dodge DLP (`ghp…` for `ghp_…`).
- **Enforces** an allowlist of sanctioned AI tools.
- **Blocks** risky prompts and data inline (HTTP 403), or just records them for triage.
- **Scans** git commits for secrets and PII before they land in a repo.
- **Scans** endpoints for credentials **at rest** (SSH/RSA keys, `.env`, tokens) before an
  infostealer does — with your own scanners too: TruffleHog / Gitleaks / GitGuardian feed the
  same console (masked at ingest; a verified-live secret escalates to critical).
- **Covers Cursor** despite its cert pinning, via a local hook that sees the prompt + tool
  calls before they run.
- **Gives** security teams a console to triage findings, manage policy, and prove coverage.

It works **offline-first**: all core detection runs on local rules without any LLM key.
An optional **LLM judge** (Claude, GPT, or Gemini) adds a frontier-model second opinion
for novel attacks the rules miss.

---

## 3. Architecture at a glance

Warden has a **hosted core** (you run it once) and several **capture planes** at the
edge (where AI traffic actually happens).

```
        CAPTURE PLANES (edge)                     HOSTED CORE (run once)
   ┌────────────────────────────┐            ┌───────────────────────────┐
   │ First-party apps / CLIs     │──/v1──────▶│  Frontend (React + nginx) │
   │  (Claude Code, OpenAI SDK)  │            │  :8080  — console         │
   ├────────────────────────────┤            ├───────────────────────────┤
   │ Browsers (claude.ai, GPT)   │            │  Backend (FastAPI)        │
   │  └─ MV3 extension           │──/api────▶ │  :8088  — API + gateway   │
   ├────────────────────────────┤  ingest    │   • detection engine      │
   │ Desktop apps / IDEs / CLIs  │            │   • LLM gateway (3 SDKs)  │
   │  └─ egress proxy (mitmproxy)│            │   • auth: OIDC/SAML/MFA   │
   ├────────────────────────────┤            │   • findings + policy     │
   │ Git commits (repos)         │──/scan────▶├───────────────────────────┤
   │  └─ pre-commit hook / CI    │  /code     │  PostgreSQL :5432         │
   └────────────────────────────┘            └───────────────────────────┘
                                              Optional LLM judge:
                                              Claude · GPT · Gemini
```

### The hosted core

| Component | Tech | Role |
|-----------|------|------|
| **Backend** | FastAPI, SQLAlchemy 2.0, Alembic, Pydantic | Detection engine, LLM gateway, auth, findings store, policy |
| **Frontend** | React 18, Vite 6 | Security-team console (dashboard, findings, settings, users, audit) |
| **Database** | PostgreSQL (prod), SQLite (dev) | Findings, users, tenants, keys, SSO config |
| **LLM judge** | Anthropic / OpenAI / Google SDKs | Optional frontier-model enrichment |

### The three capture planes

1. **LLM gateway** — Your first-party apps point their base URL at Warden instead of the
   provider. Warden inspects every prompt (and, with `GATEWAY_SCAN_RESPONSES`, the model's
   **output** for secrets/PII — response-side DLP), then forwards allowed calls upstream and
   streams the response back. Speaks four API shapes: OpenAI (`/v1/chat/completions`), the
   **OpenAI Responses API** (`/v1/responses`, used by Codex CLI), Anthropic (`/v1/messages`,
   used by Claude Code), and Gemini (`/v1beta/models/{model}:generateContent`). OpenAI/Gemini
   SDK/CLI clients can be routed here via the MDM pack's `openai.env` / `gemini.txt`.
2. **Browser extension** — A Manifest V3 extension wraps `window.fetch` on public AI
   sites, extracts the prompt before it's sent, and asks Warden for a verdict
   (allow / warn / block). Rolled out org-wide via MDM force-install — from the Chrome Web
   Store (Unlisted) or a **self-hosted CRX** (no store submission; managed devices only).
3. **Egress proxy** — A mitmproxy addon inspects TLS traffic from desktop apps, IDE
   assistants (Copilot, Cursor), and CLIs that don't run in a browser — including the
   **Gemini CLI** in all three modes (API-key, OAuth/Code Assist, Vertex). Deployed via
   system proxy + a trusted CA pushed through MDM.
4. **Cursor (local hook)** — Cursor's chat pins its cert (the proxy can't read it) and
   ignores `OPENAI_BASE_URL` (the gateway can't interpose), so **`warden-cursor-hook`** uses
   Cursor's Hooks API to inspect the prompt, shell/MCP calls, and file reads/edits locally
   *before they run* — immune to the pinning. Auto-installed by `warden connect`.
5. **Endpoint credential hygiene** — **`warden-secrets`** scans where infostealers look
   (SSH/RSA keys, `~/.aws/credentials`, `.git-credentials`, `.env`, shell history) and reports
   credentials **at rest** (surface `secrets`). Detection runs locally; only masked metadata
   leaves. It can drive **TruffleHog/Gitleaks** (`--engine`), and existing CI scanner jobs
   pipe in via **`warden-import`** → `/api/scan/import`.

Plus a **git / CI plane**: stdlib-only scanners run as a pre-commit hook or GitHub Action —
`/api/scan/code` (secrets/PII in commits), `/api/scan/deps` (dependency supply-chain, opt-in
OSV/CVE lookup), `/api/scan/mcp-config` (shadow/malicious MCP servers in `.mcp.json`),
`/api/scan/ide-extensions` (known-bad / unapproved editor plugins), and
`/api/scan/agent-rules` (hidden-instruction injection — the "rules-file backdoor" — in the
instruction files a coding agent obeys: CLAUDE.md, .cursorrules, .cursor/rules/*.mdc,
AGENTS.md, copilot-instructions.md, skill SKILL.md).

**Unified cross-vendor session audit** (`GET /api/audit/sessions`, `/api/audit/timeline`;
console **Sessions** view): an enterprise runs Claude Code, Cursor, Codex, Gemini CLI,
Copilot, browser AI and MCP side by side, each with its own partial log in its own shape.
Warden captures them all into one store and presents a single **normalized** activity
trail — every event mapped to a common shape (when / who / which vendor tool / action /
verdict / kill-chain stage), grouped per actor into sessions with a rollup (vendors
touched, event count, stages seen, peak severity, whether an attack chain fired). One
timeline across every agent product, retained on Warden's schedule — not any vendor's cap.

**Session behavioral correlation** (surface `session`): every detector above scores one
event, but the dangerous pattern is a *sequence* — an agent reads credentials, runs a
shell command, then sends data out. After each finding is stored, Warden looks across the
same actor's recent activity (a rolling `WARDEN_SESSION_WINDOW_MIN`-minute window), maps
each event to a kill-chain stage (recon → manipulation → collection → execution →
exfiltration), and when the window crosses into a payoff stage across **multiple events**
it records one escalated `session_correlation` finding scoring the *chain* — the Nx
"s1ngularity" shape that no single event trips. On by default (`WARDEN_SESSION_CORRELATION`).

The gateway and egress proxy also inspect **agentic tool-use over MCP** (surface `mcp`):
an AI coding agent's tool calls, arguments, and results ride the LLM traffic, so Warden
catches sensitive-file access, dangerous commands, tool poisoning, and untrusted servers —
including **local stdio MCP** — and blocks on the request, response, or mid-stream, with no
endpoint agent. Enforcement config for managed devices is generated by `/api/policy-pack`
(editor allowlist, system proxy, browser force-install, CA note, Claude Code managed
settings, OpenAI/Gemini gateway routing, Cursor hooks, and a scheduled `warden-secrets`
scan that drives TruffleHog by default) and applied by the org's MDM.

**Onboarding is managed or self-serve.** Fleets get zero-touch config via MDM; BYOD users
sign in (login/SSO) to bind their tenant — the extension's **Sign in to Warden** and
**`warden connect`** for Claude Code mint a per-user, revocable key (no token distribution).

**Agentless by default, with optional local sensors.** The above needs no endpoint agent.
For deeper local coverage (e.g. local stdio MCP servers the network can't see), opt-in
stdlib sensors run on the device: **`warden-mcp`** (stdio-MCP wrapper, inline inspection),
**`warden-hook`** (Claude Code prompts + tool calls, pre-execution), **`warden-cursor-hook`**
(Cursor prompts + tool calls), **`warden-codex-hook`** (Codex CLI prompts + tool calls),
**`warden-gemini-hook`** (Gemini CLI prompts + tool calls), **`warden-copilot-hook`**
(GitHub Copilot tool calls — deniable — + prompts, across Copilot CLI, VS Code agent
mode, and the cloud coding agent),
**`warden-posture`** (continuous IDE/MCP drift reporting),
**`warden-secrets`** (credentials at rest, optionally driving TruffleHog/Gitleaks), and
**`warden-import`** (pipe CI scanner output in). They report on a separate ingest quota so
they don't consume the gateway quota.

**All planes fail open.** If Warden is unreachable, traffic flows and tools keep
working — security controls never take the business offline.

---

## 4. How detection works

Every captured item is routed by **surface** to the right detectors, scored, and turned
into a **verdict**.

### Detectors

- **PromptThreatDetector** (surface: `llm_io`) — injection keywords ("ignore previous
  instructions"), jailbreak terms ("DAN mode"), exfiltration patterns ("reveal your
  system prompt"), and encoded smuggling (long base64, zero-width Unicode).
- **ShadowAIDetector** (surface: `ai_usage`) — PII (SSNs incl. unformatted 9-digit, emails,
  phones, Luhn-validated credit cards, IBAN / UK NINO, keyword-confirmed passport / EIN /
  routing / SWIFT / NPI / Aadhaar, single-record detection, and per-tenant custom patterns),
  **confidential business content** (`confidential_data`: marked/NDA material + Purview/MIP
  & TLP sensitivity labels — its own category, so it isn't suppressed for coding tools), known secret formats (`AKIA…`, `sk-…`, GitHub tokens)
  **plus separator-stripped variants** flagged as likely-bypass, high-entropy unlabeled
  credentials, source-code markers, confidentiality markers, and destination checks against
  the sanctioned-tool allowlist.
- **MCPGuardDetector** (surface: `mcp`) — agentic tool-use: sensitive-resource access
  (`.env`, keys), dangerous shell commands, tool poisoning (injected tool descriptions),
  and untrusted MCP servers (per-tenant/global allowlist).
- **DepGuardDetector** (surface: `deps`) — dependency-manifest supply-chain risk: install-
  script abuse, non-registry sources, known-bad packages (+ opt-in OSV CVE lookup).
- **ExtGuardDetector** (surface: `ide`) — known-bad / unapproved IDE extensions from a
  `.vscode/extensions.json` or MDM inventory list.
- **SecretsAtRestDetector** (surface: `secrets`) — credentials found at rest on a device by
  `warden-secrets` or a third-party scanner (`credential_at_rest`). Private keys / cloud +
  VCS tokens score highest; a world-readable file or a scanner-**verified live** secret
  escalates to critical.
- **LLMJudgeDetector** (optional, all surfaces) — a frontier model reads the content like
  an analyst and returns a structured `JudgeVerdict` (AI-generated likelihood, malicious
  likelihood, indicators, recommended action). It's the semantic catch-all for what regex
  can't classify — notably **unmarked confidential business content** (financials, contracts,
  roadmaps, M&A) which it emits as `confidential_data`. Provider is pluggable
  (`JUDGE_PROVIDER=auto|anthropic|openai|gemini|claude-cli|none`). `claude-cli` runs
  verdicts through the locally signed-in **Claude Code CLI** — a Claude Pro/Max/Team
  subscription carries the cost, so a self-hosted org needs no API key or credit
  balance. It is never chosen by `auto` (it routes content through the signed-in Claude
  account, so opting in must be explicit), and configured API keys still serve as
  failover behind it. On a multi-tenant deployment, an org can also **bring its own
  judge key** (Settings → LLM judge, stored encrypted, write-only): verdicts then bill
  that org's provider account, run independently of the operator's judge capacity, and
  are exempt from plan gating — the org's judge consent setting still applies.

### Scoring

Each signal carries a `weight` and a `confidence`; its contribution is `weight ×
confidence`. Signals combine via a **saturating (probabilistic) OR** — `1 − Π(1 −
contribution)` — so many weak signals don't trivially max out the score, but a single
strong one can. Attack intent drives base risk; AI-generation acts as an amplifier. The
result is a risk score `0..100` mapped to a severity: `benign / low / suspicious / high /
critical`.

### Evasion resistance

Content is normalized (NFKC Unicode, homoglyph folding, zero-width stripping) before
matching, so tricks like Cyrillic look-alikes ("Ignоre") or fullwidth text still get
caught.

### Policy

A per-tool policy layer suppresses signals that don't apply in context — e.g. Claude Code
legitimately sends source code, so `source_code_leak` is suppressed for it while secret
detection stays on.

---

## 5. Data flow examples

### A prompt to your own LLM (Claude Code)

```
1. Dev machine:  ANTHROPIC_BASE_URL=http://warden  claude   (SDK appends /v1/messages)
2. → POST /v1/messages, authenticated (API key or JWT), tenant + actor resolved
3. → engine.analyze(): PromptThreat + ShadowAI + optional LLM judge
4. → scoring fuses signals → Verdict (risk, severity)
5. → policy filter (per-tool suppression)
6. → decision:
       enforce + severity ≥ threshold  → 403 (provider-shaped error)
       otherwise                        → record finding, forward upstream, stream back
```

### Content pasted into a public AI site (browser extension)

```
1. User pastes a secret into claude.ai
2. injected.js intercepts fetch, extracts the prompt
3. → POST /api/ingest/ai-usage  (X-Warden-Token auth)
4. → ShadowAIDetector + destination check (+ optional judge)
5. → { action: allow | warn | block }
6. Extension enforces:  allow = send · warn = send + amber banner · block = don't send + red banner
```

### A git commit (git plane)

```
1. git commit → pre-commit hook → warden_git_scan.py --staged
2. → POST /api/scan/code  (API-key auth)
3. → detectors run, source_code_leak ignored (repos hold code), secrets/PII kept on
4. → per-file allow/warn/block; a block fails the commit (override: --no-verify)
```

---

## 6. Multi-tenancy & security

Warden is multi-tenant by design. Each organization ("tenant") is isolated, and the
platform ships with SaaS-grade hardening:

- **Tenant-scoped login** — email is unique per org; login takes an optional org slug.
- **Per-tenant upstream provider keys** — stored encrypted (Fernet); each org bills to
  its own AI account.
- **Per-tenant policy** — each org sets monitor/enforce, block severity, sanctioned AI
  tools, and per-tool suppression; plus judge consent (data-residency).
- **Retention policies** — per-tenant `retention_days` plus a purge endpoint.
- **Redaction at rest** — findings mask secrets/PII so the DB isn't a plaintext honeypot;
  optional full content encryption at rest.
- **SSO** — OIDC and SAML 2.0, per tenant, with auto-provisioning.
- **MFA** — TOTP with recovery codes; "log out everywhere" session revocation.
- **Admin audit log** — per-tenant record of privileged actions.
- **Rate limiting** — DB-backed per-minute quotas (separate gateway and sensor/ingest limits).
- **Compliance & data control** — a signed DPA record, full self-serve data export (secrets
  excluded), and one-click delete-my-org.
- **SSRF-guarded** — user-set URLs the server fetches (alert webhook, SIEM collector,
  per-tenant gateway upstream) reject private/loopback/metadata hosts.
- **No forgeable keys** — the app refuses to boot without `WARDEN_SECRET_KEY` on a
  production (non-SQLite) deployment.

---

## 7. The console (frontend)

The security-team UI provides:

- **Dashboard** — counters and by-surface breakdowns, recent findings.
- **Findings** — filterable list; detail view shows every signal and the forensic
  breakdown; triage status (open / triaged / dismissed).
- **Connect** — generates copy-paste install configs for the extension, gateway, and proxy,
  plus the downloadable **MDM policy pack**.
- **Connections** — active capture keys + enrollment tokens, with one-click revoke.
- **Users** — add users, set roles (admin / analyst), enable/disable (protects the last admin).
- **Settings** — org config (name, judge consent, retention, rate limits), **per-tenant
  policy** (monitor/enforce, block severity, sanctioned tools, suppression), supply-chain
  allow/deny lists, upstream keys, SSO, MFA, **alerts** (Slack real-time or hourly/daily
  digests — criticals always real-time), **SIEM** (JSONL export + real-time push forwarding
  — Splunk HEC / JSON / CEF), and **compliance** (DPA, data export, delete-my-org).
- **Audit** — the admin action log.
- **Coverage** — compares "who used AI" from your IdP/CASB against captured findings to
  surface blind spots.
- Public **Landing**, **Login**, and **Legal** (`/privacy`, `/terms`) pages.

---

## 8. Deploying Warden

**Hosted (default).** Warden is a managed SaaS — customers don't run infrastructure. Sign in
to the console, open **Connect → Quick start**, and push the generated config (MDM pack or a
per-OS installer). Everything below is for **local development, evaluation, or self-hosting**.

**Docker Compose (self-host / eval)** — brings up Postgres + backend + nginx-served frontend:

```bash
docker compose up --build
# open http://localhost:8080
```

**From source (dev):**

```bash
# backend
cd backend && python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# frontend
cd frontend && npm install && npm run dev
```

**Production (bare metal):** systemd units and an env file live in `deploy/`; point
`DATABASE_URL` at a durable Postgres instance.

### Key configuration

| Variable | Purpose |
|----------|---------|
| `WARDEN_SECRET_KEY` | Signs JWTs — required in production |
| `DATABASE_URL` | Postgres connection string |
| `JUDGE_PROVIDER` | `auto` / `anthropic` / `openai` / `gemini` / `claude-cli` / `none` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` | LLM judge keys |
| `JUDGE_CLI_BIN` / `JUDGE_CLI_TIMEOUT` | Claude Code binary + per-verdict timeout for `claude-cli` (subscription-auth judge, self-hosted) |
| `GATEWAY_ENFORCE` | `true` = block risky prompts; `false` = monitor only |
| `GATEWAY_BLOCK_SEVERITY` | Severity threshold for blocking |
| `EXTENSION_INGEST_TOKEN` | Shared auth token for extension/proxy |
| `SANCTIONED_AI_TOOLS` | Allowlist of approved AI destinations |
| `GATEWAY_TOOL_SUPPRESS` | Per-tool signal suppression |
| `CORS_ORIGINS` | Allowed frontend origins |

---

## 9. Where things live

| Area | Path |
|------|------|
| Detection engine & scoring | `backend/app/engine.py`, `backend/app/scoring.py` |
| Detectors | `backend/app/detectors/{prompt_threats,shadow_ai,mcp_guard,dep_guard,ext_guard,secrets_at_rest,llm_judge}.py` |
| LLM gateway (incl. `/v1/responses`) | `backend/app/gateway.py` |
| Scanner import (TruffleHog/Gitleaks/GitGuardian) | `backend/app/scanner_import.py` |
| MDM policy pack | `backend/app/policy_pack.py` |
| API routes & auth | `backend/app/main.py`, `backend/app/auth.py` |
| Data models | `backend/app/models.py` |
| Config | `backend/app/config.py`, `backend/.env.example` |
| Browser extension | `extension/` |
| Egress proxy | `proxy/warden_addon.py` |
| Git scanner | `git/warden_git_scan.py` |
| Local sensors / onboarding CLI | `cli/` (warden-connect, -hook, -cursor-hook, -mcp, -posture, -secrets, -import) |
| Console (frontend) | `frontend/src/` |
| Deep-dive docs | `docs/{setup,tokens-and-identity,claude-deployment,multi-tenant-hardening}.md` |

---

## 10. Design principles

1. **Offline-first** — full detection with no LLM key; the judge is optional enrichment.
2. **Fail open** — Warden being down never blocks the business.
3. **Multi-surface routing** — rules apply only where they belong (attacks vs. leakage vs. code).
4. **Saturating scoring** — weak signals accumulate sensibly; strong ones dominate.
5. **Redaction & encryption at rest** — the findings DB is not a secret honeypot.
6. **Provider-agnostic** — one judge prompt, three interchangeable backends.
7. **Evasion-resistant** — normalize before matching so look-alike tricks fail.
