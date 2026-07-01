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

## Next tracks

### 1. Per-tenant upstream provider keys (blocker for real SaaS)
Today `GATEWAY_ANTHROPIC_KEY` / `GATEWAY_GEMINI_KEY` / `GATEWAY_UPSTREAM_KEY` are **global
env** — every org's gateway traffic would bill to one provider account. Add per-tenant
upstream config (each org's own key + base URL), stored **encrypted**, resolved by the
authenticated tenant on each gateway call.

### 2. Data security & compliance
- **Encryption at rest** for finding content and per-tenant secrets (e.g. app-level
  envelope encryption, ideally per-tenant keys).
- **Retention + hard delete** per tenant (scheduled purge; "delete my organization" for
  GDPR/CCPA).
- **Claude judge opt-in per tenant** — the judge ships content to Anthropic, so it needs
  per-tenant consent and a DPA rather than a single global `ANTHROPIC_API_KEY`.
- **Per-tenant data export** (self-serve).

### 3. Auth for SaaS
- **argon2id** password hashing and a **vetted JWT library** (replace the stdlib
  PBKDF2/HS256 minimal-deps implementation).
- **Token revocation** (logout-all / compromised key) — currently JWTs are valid until
  expiry.
- **SSO / SAML / OIDC per tenant** and **MFA**.
- Per-tenant signup/onboarding controls (the global `WARDEN_ALLOW_SIGNUP` isn't enough).

### 4. Abuse, quotas & metering
- **Per-tenant rate limits** on the gateway/ingest (noisy-neighbor isolation).
- **Usage metering** for billing and quota enforcement.

### 5. Operational
- Back the login throttle prune with an index-friendly job (or TTL) at high volume.
- Per-tenant **audit log** of admin actions (user/role/key changes).
- Metrics (Prometheus) + `/readyz`, and horizontal-scale runbook (all state is in
  Postgres today — keep it that way; no per-process state).
