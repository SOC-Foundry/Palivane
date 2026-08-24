# 05. Business Continuity & Disaster Recovery

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual + after each drill

## Objectives (measured, not guessed)

- **RPO ≤ 24 h nominal, minutes typical**, daily automated Cloud SQL backups plus
  14-day point-in-time recovery (WAL).
- **RTO ≈ 1 h**, the 2026-07-19 drill measured ~35 min for a full PITR clone to
  accepting connections (plus a few minutes' settle), verified row-by-row; budget an
  hour end-to-end with traffic cutover.

## Architecture for resilience

Stateless app on Cloud Run (min 1 instance, autoscaling, previous revisions retained);
state confined to Cloud SQL (private-IP, automated backups + PITR) and Secret Manager
(replicated). Everything needed to rebuild from zero is in the repo: Terraform for the
infra shell, deploy.sh for the app, wrangler config for the edge. DNS/edge failure
modes are Cloudflare's; origin failure modes are Google's; a region-wide us-central1
loss is accepted risk at current scale (documented in the risk register).

## Recovery procedures

- **App regression** → shift Cloud Run traffic to the prior revision (minutes).
- **Data corruption/loss** → PITR clone to a fresh instance at the last good moment,
  verify (tenants/users/findings counts + alembic head, as drilled), repoint
  `palivane-database-url`, redeploy.
- **Full project loss** → Terraform apply in a new project + restore from backup +
  re-create secrets; expected within a business day.

## Drills

Restore drill **semiannually** (next due ~2027-01), using the drilled runbook: PITR
clone → one-off Cloud Run job verification → teardown. Results recorded in the
compliance calendar evidence.

## Continuity of operations

Single-operator dependency is the top continuity risk (see risk register): mitigations
are this documentation (all procedures runnable by a competent engineer from the repo),
IaC, and, as the business grows, the first ops-capable hire.
