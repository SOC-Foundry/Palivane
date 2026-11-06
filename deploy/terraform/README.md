# Palivane — Terraform (GCP)

Infrastructure-as-code for a Palivane environment on Cloud Run: VPC + private Cloud SQL,
Artifact Registry, Secret Manager, service accounts/IAM, and the Cloud Run v2 service.
Use it to stand up a **new** environment (staging, a customer self-host) or to codify the
existing production by importing.

> The container **image** is built and pushed out-of-band (`deploy/cloudrun/deploy.sh` or
> CI) — Terraform references a tag and deliberately ignores image drift so it doesn't fight
> your deploys. The **Cloudflare Worker** front door is also out-of-band (`deploy/cloudflare`);
> Terraform just creates the `palivane-front` service account it runs as.

## What it provisions
- Custom VPC + subnet, private-services-access peering (for Cloud SQL private IP)
- Cloud SQL Postgres 16, **private IP only**, automated backups + PITR, deletion-protected
- Artifact Registry (Docker)
- Secret Manager: `palivane-secret-key`, `palivane-database-url`, `palivane-metrics-token`
  (generated/composed by TF), `palivane-smtp-pass` (container only — value added out-of-band)
- Runtime SA (`palivane-run`) with least-privilege roles; Worker SA (`palivane-front`)
- Cloud Run v2 service: direct VPC egress, Cloud SQL socket, secret env, scaling, CPU boost

## First-time apply (new environment)
```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # edit
export TF_VAR_db_password="$(openssl rand -base64 24)"   # keep it out of the file

terraform init
terraform apply
```
Then, because the SMTP secret is created empty:
```bash
# only if you set smtp_host — add the value BEFORE the service references it
printf '%s' 'YOUR_APP_PASSWORD' | gcloud secrets versions add palivane-smtp-pass --data-file=-
```
Grab `terraform output front_service_account`, add it to `invoker_members`, and re-apply so
the Cloudflare Worker can invoke the service. Build/push an image and deploy it (the
`deploy/cloudrun` script or CI); TF won't overwrite the running image.

## State holds sensitive values
`PALIVANE_SECRET_KEY`, the DB password (in `DATABASE_URL`), and the metrics token are written
to state. **Use the encrypted GCS backend** (uncomment it in `versions.tf`) — don't keep
local state. Losing/rotating `PALIVANE_SECRET_KEY` means data loss (it encrypts findings and
signs sessions), so treat the state + backend as secrets.

## Adopting a hand-built environment
Not needed for the `palivane` environment — it was provisioned by this config from empty,
so everything is already in state. **Do not run `import.sh` against it.**

The path exists for a deployment someone built by hand, where a plain `apply` would try to
*create* resources that already exist. Set **`adopt_existing = true`** and run **`import.sh`**
with that project — the flag makes the config safe for a live environment automatically
(skips generating secret versions so real values stand, and uses the default compute SA
instead of creating `palivane-run`):
```bash
terraform init -backend-config="bucket=<STATE_BUCKET>" -backend-config="prefix=palivane"
echo 'adopt_existing = true' >> terraform.tfvars
PROJECT_ID=<the-hand-built-project> ./import.sh
terraform plan   # expect a clean no-op (no destroys, no secret-version creates)
```
Keep `adopt_existing = true` for all future plans/applies against such an environment.
Fresh environments leave it `false` (the default) to provision with a dedicated SA and
generated secrets.
Caveats when importing prod: it runs as the **default compute SA**, not `palivane-run` (either
keep using it via a variable/import or migrate); `deletion_protection=true` on the SQL
instance is intentional; and the Cloudflare Worker + org DRS policy are out of this config's
scope.

## Notes
- **No `allUsers` invoker** — the org's domain-restricted-sharing policy forbids it; public
  reach is via the Worker (running as `palivane-front`). Set `invoker_members` accordingly.
- Background loops (alert digests, content-TTL scrub) run when the instance has CPU; with
  `min_instances=0` + CPU idle they run during traffic/cold-starts, same as the current prod.

## Split CI/CD identities

`service-accounts.tf` replaces the one owner-equivalent CI account with three (security review
H7, M12):

| Account | Repo variable | Used by | Can |
| --- | --- | --- | --- |
| `palivane-release` | `GCP_DEPLOY_SA` | `deploy.yml` (every merge) | build, deploy Cloud Run, sign the release with KMS, read the dataset |
| `palivane-dataset` | `GCP_DATASET_SA` | `catalog-growth.yml` | objects in the MCP dataset bucket |
| `palivane-deploy` (existing) | `GCP_INFRA_SA` | `terraform-apply.yml`, `ops.yml` (dispatched by hand) | everything, as before |

Each account is bound to one GitHub environment's OIDC subject
(`repo:<owner/name>:environment:<env>`), so the WIF provider needs no change. The dataset
workflow's build job, which parses data from the internet, has no `id-token` permission, so it
can't mint a token for any account.

Cutover, in order (each Terraform step: a plan-only dispatch first, then apply):

1. Move release signing to KMS first (`deploy/gcp/import-release-key.sh`, then
   `RELEASE_KMS_KEY_VERSION`). The release account deliberately can't read the signing-key secret.
2. Apply. This creates the two accounts and their roles; nothing uses them yet.
3. Set `GCP_INFRA_SA` to `palivane-deploy@<project>.iam.gserviceaccount.com`, then
   `GCP_DEPLOY_SA` to the `release_sa_email` output and `GCP_DATASET_SA` to `dataset_sa_email`.
   Apply again (it moves the KMS signer binding to the release account).
4. Merge or dispatch a deploy and run `catalog-growth.yml`. If either fails on a permission,
   set `GCP_DEPLOY_SA` back to `palivane-deploy` and report the missing role.
5. Set the repo variable `SCOPE_INFRA_IDENTITY=true` and apply: `palivane-deploy` then answers
   only to `production-infra` jobs.
