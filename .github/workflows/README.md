# CI/CD workflows

- **ci.yml** (pull requests) — backend pytest, frontend build, `terraform fmt`/`validate`,
  and a `terraform plan` (same-repo PRs only, when GCP creds are configured) posted to the
  job summary so infra diffs are reviewed before merge.
- **deploy.yml** (push to `main`, excluding infra/docs paths) — builds + pushes the image
  (Cloud Build) and deploys to Cloud Run via `deploy/cloudrun/deploy.sh`.
- **terraform-apply.yml** (push to `main` touching `deploy/terraform/**`) — `terraform apply`
  for infra changes, kept separate from app deploys.

## Auth — Workload Identity Federation (no long-lived keys)
Create a WIF pool/provider bound to a deploy service account, and grant that SA:
`roles/run.admin`, `roles/cloudbuild.builds.editor`, `roles/artifactregistry.writer`,
`roles/iam.serviceAccountUser` (to act as the runtime SA), `roles/storage.admin` (TF state
bucket), plus the roles Terraform needs to manage the resources (`roles/cloudsql.admin`,
`roles/compute.networkAdmin`, `roles/secretmanager.admin`, `roles/resourcemanager.projectIamAdmin`).

## Configure these in GitHub (Settings → Secrets and variables → Actions)

**Repository variables (`vars.`)** — non-sensitive:
`GCP_PROJECT_ID`, `GCP_REGION`, `GCP_SQL_CONNECTION`, `GCP_WORKLOAD_IDENTITY_PROVIDER`,
`GCP_DEPLOY_SA`, `TF_STATE_BUCKET`, `VPC_NETWORK`, `VPC_SUBNET`, `GATEWAY_ENFORCE`,
`WARDEN_ALLOW_SIGNUP`, `WARDEN_ENCRYPT_FINDINGS`, `DOMAIN`, `WARDEN_ALLOWED_HOSTS`,
`WARDEN_EXTENSION_ID`, `SMTP_HOST`, `SMTP_USER`, `MAIL_FROM`, `DEPLOY_IMAGE`.

**Repository secrets (`secrets.`)** — sensitive:
`TF_DB_PASSWORD` (Postgres user password for Terraform).

**Environments** — create `production` (deploy) and `production-infra` (terraform apply)
and add required reviewers for a manual approval gate before anything hits prod.

> App secrets themselves (WARDEN_SECRET_KEY, warden-smtp-pass, provider keys) live in
> Secret Manager, not GitHub — the workflows never handle them.
