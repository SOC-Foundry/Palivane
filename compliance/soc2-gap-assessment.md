# SOC 2 readiness — gap assessment

Scope: Security + Confidentiality + Availability. Assessed 2026-09 against the running
system (not aspirations). Evidence pointers name the code, config, or console surface an
auditor can be shown.

## What already exists (design in place, evidence self-generating)

| Control | Evidence |
|---|---|
| Encryption in transit | Cloudflare TLS at edge; IAM-authenticated origin (Cloud Run invoker locked to the Worker) — `deploy/terraform`, `/trust` |
| Encryption at rest + per-tenant envelope encryption | Cloud SQL disk encryption; finding content sealed under per-tenant DEKs (`app/crypto.py`); connector credentials sealed per tenant |
| Tenant isolation | Postgres Row-Level Security on tenant-scoped tables (`*_rls_tenant_isolation` migration) beneath app-level scoping |
| Access control (product) | Admin/analyst roles; SSO (OIDC + SAML), TOTP MFA, token_version session revocation; SCIM 2.0 lifecycle (deactivation kills sessions) |
| Access control (infra) | Prod GCP has **no human credentials** — GitHub-Actions WIF only; admin CLI via `ops.yml` runs; secrets exclusively in Secret Manager |
| Audit logging | Per-org `audit_log` (admin actions, overrides, SCIM mutations, remediations); Cloud Run request logs; GitHub audit trail |
| Change management (partial) | All changes via PR → 4 CI gates → squash-merge; deploys are a **manual, logged** workflow run; images tagged by git SHA |
| Backups | Cloud SQL automated backups + point-in-time recovery (`deploy/terraform/sql.tf`) |
| Data retention & deletion | Per-org retention (content TTL separate from metadata), full JSON export, self-serve org deletion |
| DPA | Versioned in-product acceptance, recorded with who/when |
| Vulnerability mgmt (partial) | Dependabot-class updates via PRs; internal security bug bash (#106–#107) with fixes shipped |
| IaC | Terraform-defined production, drift-free state |

## Gaps (the actual work)

**P0 — close before the observation window starts**

| # | Gap | Action | Notes |
|---|---|---|---|
| 1 | **No branch protection on `main`** | Upgrade the GitHub org to Team ($4/user/mo) and require PRs + passing checks on `main` | GitHub Free doesn't offer protection on private repos — today nothing *technically* stops a direct push; the PR-only history is convention |
| 2 | **No uptime monitoring / availability evidence** | GCP uptime checks on `palivane.io` + `app.palivane.io/api/health`, alerting to email/Slack; add a public status page later | Availability criterion needs measured uptime, not vibes |
| 3 | **Solo-maintainer change review** | Document compensating controls (CI gates, protected main, deploy separation, post-merge review cadence) in the change-mgmt policy; add a second reviewer when headcount allows | Auditors accept documented compensating controls for small teams |
| 4 | **Restore-test cadence** | /trust records a verified drill (July 2026, ~35 min full restore); the gap is the CADENCE — calendar a quarterly drill (next due Oct 2026) and file each write-up here | A backup nobody restored recently is a hope, not a control |
| 5 | **No formal risk assessment** | Complete `risk-register.md` (started); review annually | |
| 6 | **No vendor register / reviews** | Complete `vendor-register.md` (started); annual review of critical vendors' SOC 2 reports | GCP, Cloudflare, GitHub, Stripe, Google Workspace, model providers |

**P1 — during the observation window**

| # | Gap | Action |
|---|---|---|
| 7 | Security awareness training | Annual training with completion records (platform-provided module is fine) |
| 8 | Background checks | For all new hires; document founder exception rationale |
| 9 | Quarterly access reviews | Calendar + recorded review of GCP IAM, GitHub, Workspace, Cloudflare, Stripe access |
| 10 | Incident response test | One tabletop exercise per period, written up |
| 11 | Endpoint security | Disk encryption + screen lock + updates on all workstations, attested (MDM or platform agent when >1 person) |
| 12 | External penetration test | Annual third-party pentest (the internal bug bash doesn't count as independent) |
| 13 | Formal on/offboarding checklist | Even at n=1: the checklist is the control |

**Platform decision (deferred)**: Sprinto-class (~$5–8k/yr) vs Vanta/Drata (~$12–25k/yr) vs
DIY. Recommendation stands: a budget platform — automated evidence from GCP/GitHub/Workspace
integrations pays for itself in avoided screenshot archaeology, and the **policy pack should
be authored in the platform once chosen** (they ship maintained templates that map to their
own evidence checks — writing the pack twice is waste; this repo keeps the decisions and
the honest gap list).

## Confidentiality criterion notes
Covered largely by existing design: per-tenant DEKs, metadata-first storage default,
redaction before persistence, retention + deletion, RLS. Remaining: data-classification
statements in the policy pack and confidentiality commitments consistency check across
ToS/DPA.

## Availability criterion notes
Needs: uptime monitoring (gap #2), documented BCDR with RTO/RPO (Cloud Run is
multi-instance; Cloud SQL PITR gives RPO in minutes — write the numbers down), restore
tests (gap #4), and capacity/error alerting (ops webhook exists for judge health; extend
to 5xx-rate alerting).
