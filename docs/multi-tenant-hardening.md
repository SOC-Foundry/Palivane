# Multi-tenant hosting — hardening roadmap

Warden was designed multi-tenant (every query is scoped to `tenant_id`, with cross-tenant
isolation tests). This tracks what's needed to host it as a **shared SaaS** serving many
orgs, versus a single-org self-host. Done items are shipped; the rest are sequenced tracks.

## Done
- **Tenant-scoped login.** Email is unique only *within* a tenant, so login accepts an
  optional `org` (slug). An email that exists in multiple orgs must specify one — Warden
  never auto-picks a tenant (that would be a cross-tenant hazard). Single-org/demo login
  omits `org`.
- **Shared-state brute-force throttle.** Failed logins are recorded in the DB
  (`login_attempts`) and limited per **email** and per **IP** within a window — so the
  limit holds across workers/replicas, not per-process.
- **Redaction at rest.** Stored finding content masks secrets/PII so one shared DB isn't a
  plaintext-secret honeypot (`WARDEN_REDACT_FINDINGS`).
- **Tenant isolation.** Data endpoints scope to the caller's tenant; API keys are
  tenant-scoped; cross-tenant access returns 404. Covered by tests.
- **Per-tenant upstream provider keys.** Each org can set its own OpenAI / Anthropic /
  Gemini base URL + key (`PUT /api/upstreams/{provider}`), stored **encrypted at rest**
  (`crypto.py`, Fernet keyed from `WARDEN_ENCRYPTION_KEY`/`WARDEN_SECRET_KEY`). The
  gateway resolves the calling tenant's config per request and forwards allowed calls with
  *its* key — so gateway traffic bills to each org's own provider account, not one shared
  account. Falls back to the global env config when a tenant hasn't set one.

## Next tracks

### 1. Data security & compliance
- **Encryption at rest** for finding content and per-tenant secrets (e.g. app-level
  envelope encryption, ideally per-tenant keys).
- **Retention + hard delete** per tenant (scheduled purge; "delete my organization" for
  GDPR/CCPA).
- **Claude judge opt-in per tenant** — the judge ships content to Anthropic, so it needs
  per-tenant consent and a DPA rather than a single global `ANTHROPIC_API_KEY`.
- **Per-tenant data export** (self-serve).

### 2. Auth for SaaS
- **argon2id** password hashing and a **vetted JWT library** (replace the stdlib
  PBKDF2/HS256 minimal-deps implementation).
- **Token revocation** (logout-all / compromised key) — currently JWTs are valid until
  expiry.
- **SSO / SAML / OIDC per tenant** and **MFA**.
- Per-tenant signup/onboarding controls (the global `WARDEN_ALLOW_SIGNUP` isn't enough).

### 3. Abuse, quotas & metering
- **Per-tenant rate limits** on the gateway/ingest (noisy-neighbor isolation).
- **Usage metering** for billing and quota enforcement.

### 4. Operational
- Back the login throttle prune with an index-friendly job (or TTL) at high volume.
- Per-tenant **audit log** of admin actions (user/role/key changes).
- Metrics (Prometheus) + `/readyz`, and horizontal-scale runbook (all state is in
  Postgres today — keep it that way; no per-process state).
