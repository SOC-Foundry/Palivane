# 03 — Change Management Policy

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## The gate (enforced, not aspirational)

All changes to `main` — and therefore to production — flow through GitHub branch
protection that even repo admins cannot bypass:

1. Change developed on a short-lived branch; test suite run locally.
2. Pull request opened; CI must pass: `backend-tests` (700+ tests), `frontend-build`,
   `selfhost-compose` (whole-stack boot), plus Terraform validate/plan on infra diffs.
3. Merge is rebase-only (linear history); force pushes and branch deletion on `main`
   are blocked.

**Single-operator compensating control:** with one engineer there is no second human
reviewer; the required-CI gate, immutable PR history, and this policy are the
documented compensating controls. Required approvals will be raised to ≥1 with the
first engineering hire.

## Deployment

- **Application:** `deploy/cloudrun/deploy.sh` builds via Cloud Build and deploys the
  commit-tagged image; database migrations run in the container entrypoint (Alembic)
  before serving. Every prod deploy corresponds to a commit on protected `main`.
- **Infrastructure:** Terraform (`deploy/terraform/`, state in GCS). The infra shell is
  IaC-owned; `terraform plan` runs in CI on infra PRs.
- **Edge:** the Cloudflare Worker deploys from the repo via wrangler; its config is
  version-controlled.

## Emergency changes

Fix-forward through the same PR gate (CI is fast enough); if the platform itself
prevents that, the emergency action is taken, then reconstructed as a PR within 24 h
and noted in the incident record.

## Rollback

Cloud Run retains prior revisions — traffic can be shifted back in minutes. Database
migrations ship with downgrade paths; data-loss-bearing rollbacks trigger Policy 05.
