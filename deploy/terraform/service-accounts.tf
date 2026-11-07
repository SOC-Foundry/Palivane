# Split CI/CD identities (security review H7, M12). One owner-equivalent account used to do
# everything: the automatic deploy on every merge, Terraform, ops jobs and the weekly
# dataset job. Now:
#
#   release  (new, GCP_DEPLOY_SA)   deploy.yml: build the image, deploy the Cloud Run service,
#                                   sign the CLI release with KMS. No secret payloads, no IAM.
#   dataset  (new, GCP_DATASET_SA)  catalog-growth.yml: objects in the MCP dataset bucket only.
#   infra    (the existing palivane-deploy, GCP_INFRA_SA)
#                                   terraform-apply.yml and ops.yml, both dispatched by hand.
#
# Each is impersonable only from its own GitHub environment: GitHub's OIDC subject for an
# environment job is "<prefix>:environment:<env>", so the bindings name that subject and the
# existing WIF provider needs no change. The prefix is "repo:<owner/name>", or with immutable
# subjects on (this repo) "repo:<owner>@<owner_id>/<name>@<repo_id>"; terraform-apply.yml
# passes the latter.
#
# Cutover (deploy/terraform/README.md, "Split CI/CD identities"):
#   1. Release signing on KMS first (RELEASE_KMS_KEY_VERSION): the release SA has no access
#      to the signing-key secret, by design.
#   2. Apply this (scope_infra_identity = false). Set GCP_DEPLOY_SA to the release SA,
#      GCP_DATASET_SA to the dataset SA, GCP_INFRA_SA to palivane-deploy.
#   3. After a deploy and a dataset run succeed, apply with scope_infra_identity = true: the
#      infra SA then answers only to production-infra (terraform, ops).

locals {
  wif_pool       = var.wif_provider != "" ? replace(var.wif_provider, "/\\/providers\\/.*$/", "") : ""
  sub_prefix     = var.github_oidc_sub_prefix != "" ? var.github_oidc_sub_prefix : "repo:${var.github_repo}"
  env_subject    = { for env in ["production", "production-infra"] : env => "principal://iam.googleapis.com/${local.wif_pool}/subject/${local.sub_prefix}:environment:${env}" }
  wif_ready      = local.wif_pool != "" && var.github_repo != ""
  cloudbuild_bkt = "${var.project_id}_cloudbuild"
}

resource "google_service_account" "release" {
  account_id   = "${var.service_name}-release"
  display_name = "Palivane deploy (build, Cloud Run, release signing)"
}

resource "google_service_account" "dataset" {
  account_id   = "${var.service_name}-dataset"
  display_name = "Palivane MCP dataset job (one bucket)"
}

# --- release: what deploy/cloudrun/deploy.sh does ------------------------------------------
resource "google_project_iam_member" "release" {
  # run.admin: deploy the service and its invoker policy. builds.editor + serviceUsageConsumer:
  # gcloud builds submit. secretmanager.viewer: list the secret versions to bind, never read them.
  for_each = toset([
    "roles/run.admin",
    "roles/cloudbuild.builds.editor",
    "roles/serviceusage.serviceUsageConsumer",
    "roles/secretmanager.viewer",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.release.email}"
}

# Deploying a service that runs as the runtime SA, and a build that runs as the default
# compute SA, both need actAs on that account.
resource "google_service_account_iam_member" "release_act_as" {
  for_each           = toset(distinct([local.run_sa_email, local.compute_sa]))
  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value}"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.release.email}"
}

# Cloud Build's source staging bucket.
resource "google_storage_bucket_iam_member" "release_build_source" {
  bucket = local.cloudbuild_bkt
  role   = "roles/storage.admin"
  member = "serviceAccount:${google_service_account.release.email}"
}

resource "google_artifact_registry_repository_iam_member" "release_push" {
  location   = google_artifact_registry_repository.palivane.location
  repository = google_artifact_registry_repository.palivane.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.release.email}"
}

# deploy.sh bakes the MCP dataset into the image.
resource "google_storage_bucket_iam_member" "release_reads_dataset" {
  bucket = google_storage_bucket.mcp_reputation.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.release.email}"
}

resource "google_kms_crypto_key_iam_member" "release_signs" {
  crypto_key_id = google_kms_crypto_key.release.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.release.email}"
}

# --- dataset: one bucket ---------------------------------------------------------------------
resource "google_storage_bucket_iam_member" "dataset_objects" {
  bucket = google_storage_bucket.mcp_reputation.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.dataset.email}"
}

# --- who may impersonate which -----------------------------------------------------------------
resource "google_service_account_iam_member" "release_wif" {
  count              = local.wif_ready ? 1 : 0
  service_account_id = google_service_account.release.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.env_subject["production"]
}

# The dataset jobs run in the production environment too (a separate environment would need
# a WIF provider change). That is acceptable because the job that parses outside data holds
# no OIDC token at all (catalog-growth.yml), so it can't mint a token for any account.
resource "google_service_account_iam_member" "dataset_wif" {
  count              = local.wif_ready ? 1 : 0
  service_account_id = google_service_account.dataset.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.env_subject["production"]
}

# The existing palivane-deploy account becomes the infra identity. Authoritative for
# workloadIdentityUser, so it REPLACES the repository-wide binding setup-wif.sh made: only
# production-infra jobs (terraform-apply.yml, ops.yml) can use it afterwards.
resource "google_service_account_iam_binding" "infra_wif" {
  count              = local.wif_ready && var.scope_infra_identity && var.infra_sa_email != "" ? 1 : 0
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.infra_sa_email}"
  role               = "roles/iam.workloadIdentityUser"
  members            = [local.env_subject["production-infra"]]
}

# The monthly Worker key rotation (.github/workflows/rotate-front-key.yml) runs as the infra
# identity: it may create and delete keys on the front-door account, and no other account's.
resource "google_service_account_iam_member" "infra_rotates_front_key" {
  count              = var.infra_sa_email != "" ? 1 : 0
  service_account_id = google_service_account.front.name
  role               = "roles/iam.serviceAccountKeyAdmin"
  member             = "serviceAccount:${var.infra_sa_email}"
}
