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

## Next tracks

### 1. Data security & compliance (remaining)
- **Full encryption at rest** for finding *content* (beyond redaction — envelope
  encryption, ideally per-tenant keys) and **self-serve data export** per tenant.
- **DPA / consent record** to accompany the judge opt-in.

### 2. Auth for SaaS (remaining)
- **SSO / OIDC per tenant** (then SAML) and **MFA** (TOTP + recovery codes).
- Per-tenant signup/onboarding controls (the global `WARDEN_ALLOW_SIGNUP` isn't enough).
- Optional: swap the hardened stdlib HS256 JWT for a vetted library (PyJWT).

### 3. Abuse, quotas & metering
- **Per-tenant rate limits** on the gateway/ingest (noisy-neighbor isolation).
- **Usage metering** for billing and quota enforcement.

### 4. Operational
- Back the login throttle prune with an index-friendly job (or TTL) at high volume.
- Per-tenant **audit log** of admin actions (user/role/key changes).
- Metrics (Prometheus) + `/readyz`, and horizontal-scale runbook (all state is in
  Postgres today — keep it that way; no per-process state).
