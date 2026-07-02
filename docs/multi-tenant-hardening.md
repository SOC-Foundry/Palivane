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
- **Data controls per tenant.** Claude-judge **opt-out** (`PATCH /api/tenant` `judge`:
  on/off/inherit — the judge ships content to Anthropic), **retention** (`retention_days`
  + `POST /api/findings/purge`, scheduler-friendly), and **delete-my-org**
  (`DELETE /api/tenant`, slug-confirmed, cascades findings/users/keys/upstreams). Stored
  finding content is already redacted at rest (`WARDEN_REDACT_FINDINGS`).
- **Password hashing & session revocation.** Passwords use **argon2id** (legacy PBKDF2
  hashes still verified and auto-upgraded on login). Sessions carry a `token_version`;
  `POST /api/auth/logout-all` bumps it to revoke all of a user's existing JWTs.
- **OIDC SSO per tenant.** Each org configures its IdP (`PUT /api/oidc`: issuer/client_id/
  secret encrypted, `auto_provision`, `allowed_domain`). Auth-code flow at
  `/api/auth/oidc/{org}/login` → `/callback` validates the ID token (JWKS signature, iss/
  aud/exp/nonce via authlib), maps/provisions the user, and hands a session to the console.
  State is a signed, self-expiring token (no server session store → multi-worker safe).
- **Gateway quotas + usage metering.** A DB-backed per-minute counter per tenant
  (`gateway_usage`) rate-limits gateway calls (per-tenant `rate_limit`, else global
  `GATEWAY_RATE_LIMIT`; 0 = unlimited) — over-limit returns a provider-shaped **429** with
  `Retry-After`. The same counter is the metering source: `GET /api/usage` reports the
  current window, last-24h, and per-day totals.
- **Admin console (Settings page).** A self-serve UI for all of the above: org settings
  (name, judge consent, retention, rate limit), a usage panel, per-provider upstream keys,
  OIDC SSO config, and "log out everywhere" — previously API-only.
- **MFA (TOTP).** Stdlib TOTP (RFC 6238) + one-time recovery codes. Enroll from Settings
  (`/api/auth/mfa/setup|confirm`); login returns a short-lived challenge when MFA is on,
  exchanged for a session via `/api/auth/mfa/verify` (TOTP or recovery code, throttled).
  The secret is encrypted at rest; recovery codes stored as hashes.
- **Admin audit log.** Security-relevant admin actions (user/role, API keys, upstreams,
  OIDC, tenant settings, MFA, session revoke, findings purge) are recorded per tenant
  (`audit_log`) and shown in a console **Audit** view; readable at `GET /api/audit`
  (admin, filterable by action).

## Next tracks

### 1. Data security & compliance (remaining)
- **Full encryption at rest** for finding *content* (beyond redaction — envelope
  encryption, ideally per-tenant keys) and **self-serve data export** per tenant.
- **DPA / consent record** to accompany the judge opt-in.

### 2. Auth for SaaS (remaining)
- **SAML** SSO (OIDC + MFA shipped).
- Per-tenant signup/onboarding controls (the global `WARDEN_ALLOW_SIGNUP` isn't enough).
- Optional: swap the hardened stdlib HS256 JWT for a vetted library (PyJWT).

### 3. Abuse, quotas & metering (remaining)
- Extend rate limiting to the **ingest** endpoints (extension/proxy), and wire usage
  into a **billing** provider.

### 4. Operational (remaining)
- Back the login throttle prune with an index-friendly job (or TTL) at high volume.
- Metrics (Prometheus) + `/readyz`, and horizontal-scale runbook (all state is in
  Postgres today — keep it that way; no per-process state).
