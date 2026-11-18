# CI/CD workflows

- **ci.yml** (pull requests, and push to `main` except docs-only paths) — backend pytest,
  frontend build plus claim and API-call checks, extension end-to-end, compose smoke,
  native install, Postgres RLS, S3/MinIO, and `terraform fmt`/`validate`. A `terraform plan`
  runs for same-repo PRs when GCP creds are configured, and is posted to the job summary.
- **deploy.yml** (after CI succeeds on `main`, and manual `workflow_dispatch`) — builds and
  deploys to Cloud Run via `deploy/cloudrun/deploy.sh` only when that CI run passed on the
  commit that is still `main`'s head. There is no `push` trigger. Set the repository
  variable `AUTO_DEPLOY=false` to stop automatic deploys; manual dispatch still works.
  A docs-only commit that CI skips is not deployed.
- **terraform-apply.yml** (manual `workflow_dispatch` only) — plan by default. Apply is a
  separate checkbox, and the job refuses a plan that would delete or replace resources
  unless `allow_core_changes` is set. The push trigger is commented out.
- **ops.yml** (manual dispatch) — runs an operator script (`python -m app.users ...`) inside
  the production image as a one-off Cloud Run job. The script comes from the `OPS_SCRIPT`
  repository secret (set it, dispatch, delete it) so passwords never appear in logs.

## Auth — Workload Identity Federation (no long-lived keys)
Create a WIF pool/provider bound to a deploy service account, and grant that SA:
`roles/run.admin`, `roles/cloudbuild.builds.editor`, `roles/artifactregistry.writer`,
`roles/iam.serviceAccountUser` (to act as the runtime SA), `roles/storage.admin` (TF state
bucket), plus the roles Terraform needs to manage the resources (`roles/cloudsql.admin`,
`roles/compute.networkAdmin`, `roles/secretmanager.admin`, `roles/resourcemanager.projectIamAdmin`).

## Configure these in GitHub (Settings → Secrets and variables → Actions)

**Repository variables (`vars.`)** — non-sensitive:
`GCP_PROJECT_ID`, `GCP_REGION`, `GCP_SQL_CONNECTION`, `GCP_WORKLOAD_IDENTITY_PROVIDER`,
`GCP_DEPLOY_SA`, `TF_STATE_BUCKET`, `VPC_NETWORK`, `VPC_SUBNET`, `GATEWAY_ENFORCE`, `PALIVANE_OCR` (optional; unset keeps image OCR on), `CLIENT_ENFORCE` (optional; unset keeps hooks in monitor),
`PALIVANE_ALLOW_SIGNUP`, `PALIVANE_ENCRYPT_FINDINGS`, `DOMAIN`, `PALIVANE_ALLOWED_HOSTS`,
`PALIVANE_EXTENSION_ID`, `SMTP_HOST`, `SMTP_USER`, `MAIL_FROM`, `CF_EMAIL_ACCOUNT_ID`,
`STRIPE_PRICE_TEAM_MONTHLY`, `STRIPE_PRICE_TEAM_ANNUAL`, `DEPLOY_IMAGE`.

`STRIPE_PRICE_TEAM_MONTHLY` and `STRIPE_PRICE_TEAM_ANNUAL` mark a deployment as
Stripe-configured so an existing subscription can use the customer portal and
webhooks. They do not open per-user Checkout. That path is closed in
`backend/app/billing.py`; Team is quoted by the protected-user bands on `/pricing`.

**Repository secrets (`secrets.`)** — sensitive:
`TF_DB_PASSWORD` (Postgres user password for Terraform).

**Environments** — create `production` (deploy) and `production-infra` (terraform apply)
and add required reviewers for a manual approval gate before anything hits prod.

> App secrets themselves (PALIVANE_SECRET_KEY, palivane-smtp-pass, provider keys) live in
> Secret Manager, not GitHub — the workflows never handle them.
