# 02 — Access Control Policy

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Principles

Least privilege, unique identities (no shared accounts), MFA on everything that
supports it, and quarterly reviews with written evidence.

## Access inventory (the systems that matter)

| System | Who | Auth |
|---|---|---|
| GCP project `erudite-calling-502022-k6` | Founder | Google account + MFA |
| GitHub `TachTech-Engineering/Warden` | Founder | GitHub account + MFA |
| Cloudflare (zone + Worker) | Founder | Cloudflare account + MFA |
| Secret Manager (all secrets incl. license signing key) | Founder + Cloud Run runtime SA | IAM |
| Warden app — tenant admin | Founder (tachtech org) | password (argon2id) + TOTP |
| Production DB | No human path — private IP only; operator tasks run as auditable one-off Cloud Run jobs | IAM |

Service accounts are single-purpose (`warden-front` for the edge, the compute SA for
runtime) and hold only the roles they need.

## In-product access control

- Roles: `admin` / `analyst` per organization; org data isolated by Postgres RLS
  beneath application-level scoping.
- Human auth: argon2id password hashing, TOTP MFA, per-org OIDC/SAML SSO, brute-force
  throttling (per-email+IP and per-IP), session revocation (`token_version`).
- Machine auth: hashed-at-rest API keys with expiry, per-device enrollment keys,
  per-user extension tokens, agent identities with short-lived (≤24 h) session tokens
  revoked instantly when the agent is disabled.

## Provisioning, review, revocation

Access is granted on documented need (today: the Founder's operating roles). A
**quarterly access review** walks the inventory above plus app-level admins and API
keys; results are dated notes in `docs/compliance/reviews/`. Offboarding (future
personnel): all access in the inventory revoked the same day, recorded on the
offboarding checklist. Emergency credential rotation follows the incident process
(Policy 04) — precedent: the 2026-07-16 DB password rotation after a suspected exposure.
