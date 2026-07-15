# Warden — Terraform (GCP)

Infrastructure-as-code for a Warden environment on Cloud Run: VPC + private Cloud SQL,
Artifact Registry, Secret Manager, service accounts/IAM, and the Cloud Run v2 service.
Use it to stand up a **new** environment (staging, a customer self-host) or to codify the
existing production by importing.

> The container **image** is built and pushed out-of-band (`deploy/cloudrun/deploy.sh` or
> CI) — Terraform references a tag and deliberately ignores image drift so it doesn't fight
> your deploys. The **Cloudflare Worker** front door is also out-of-band (`deploy/cloudflare`);
> Terraform just creates the `warden-front` service account it runs as.

## What it provisions
- Custom VPC + subnet, private-services-access peering (for Cloud SQL private IP)
- Cloud SQL Postgres 16, **private IP only**, automated backups + PITR, deletion-protected
- Artifact Registry (Docker)
- Secret Manager: `warden-secret-key`, `warden-database-url`, `warden-metrics-token`
  (generated/composed by TF), `warden-smtp-pass` (container only — value added out-of-band)
- Runtime SA (`warden-run`) with least-privilege roles; Worker SA (`warden-front`)
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
printf '%s' 'YOUR_APP_PASSWORD' | gcloud secrets versions add warden-smtp-pass --data-file=-
```
Grab `terraform output front_service_account`, add it to `invoker_members`, and re-apply so
the Cloudflare Worker can invoke the service. Build/push an image and deploy it (the
`deploy/cloudrun` script or CI); TF won't overwrite the running image.

## State holds sensitive values
`WARDEN_SECRET_KEY`, the DB password (in `DATABASE_URL`), and the metrics token are written
to state. **Use the encrypted GCS backend** (uncomment it in `versions.tf`) — don't keep
local state. Losing/rotating `WARDEN_SECRET_KEY` means data loss (it encrypts findings and
signs sessions), so treat the state + backend as secrets.

## Adopting the EXISTING production (don't clobber it)
The live prod was created by hand, so a plain `apply` against that project would try to
*create* resources that already exist and error (or, worse, diverge). To codify it safely,
**import** each resource first, then `plan` until it's a no-op:
```bash
terraform import google_sql_database_instance.warden   PROJECT/warden-db
terraform import google_compute_network.vpc            projects/PROJECT/global/networks/warden-vpc
terraform import google_artifact_registry_repository.warden  projects/PROJECT/locations/us-central1/repositories/warden
terraform import google_cloud_run_v2_service.warden    projects/PROJECT/locations/us-central1/services/warden
# ...secrets, subnetwork, PSA address, service-networking connection, IAM members similarly
```
Caveats when importing prod: it runs as the **default compute SA**, not `warden-run` (either
keep using it via a variable/import or migrate); `deletion_protection=true` on the SQL
instance is intentional; and the Cloudflare Worker + org DRS policy are out of this config's
scope.

## Notes
- **No `allUsers` invoker** — the org's domain-restricted-sharing policy forbids it; public
  reach is via the Worker (running as `warden-front`). Set `invoker_members` accordingly.
- Background loops (alert digests, content-TTL scrub) run when the instance has CPU; with
  `min_instances=0` + CPU idle they run during traffic/cold-starts, same as the current prod.
