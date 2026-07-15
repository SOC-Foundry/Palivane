data "google_project" "this" {}

# Runtime identity for Cloud Run. Fresh deploy: create a dedicated least-privilege
# `warden-run` SA and bind its roles. adopt_existing: reuse the default compute SA the
# hand-built prod already runs as (it already holds the needed roles — don't manage them).
resource "google_service_account" "run" {
  count        = var.adopt_existing ? 0 : 1
  account_id   = "${var.service_name}-run"
  display_name = "Warden Cloud Run runtime"
}

locals {
  run_roles = [
    "roles/cloudsql.client",
    "roles/secretmanager.secretAccessor",
    "roles/logging.logWriter",
  ]
  # The compute SA to fall back to when adopting (auto-derived from the project number).
  compute_sa = var.compute_sa_email != "" ? var.compute_sa_email : "${data.google_project.this.number}-compute@developer.gserviceaccount.com"
  # The identity the service actually runs as.
  run_sa_email = var.adopt_existing ? local.compute_sa : one(google_service_account.run[*].email)
}

resource "google_project_iam_member" "run" {
  # Only manage role bindings for the SA we create; the compute SA already has them.
  for_each = var.adopt_existing ? toset([]) : toset(local.run_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${local.run_sa_email}"
}

# Front-door identity for the Cloudflare Worker (mints an ID token to invoke the private
# service). The Worker deployment itself is out-of-band (deploy/cloudflare).
resource "google_service_account" "front" {
  account_id   = "${var.service_name}-front"
  display_name = "Warden Cloudflare Worker front door"
}

# Who may invoke the service: the Worker SA always, plus any members from var.invoker_members
# (human users, etc.). NOT allUsers — org DRS policy forbids it; public access is via the Worker.
resource "google_cloud_run_v2_service_iam_member" "invoker_front" {
  name     = google_cloud_run_v2_service.warden.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.front.email}"
}

resource "google_cloud_run_v2_service_iam_member" "invokers" {
  for_each = toset(var.invoker_members)
  name     = google_cloud_run_v2_service.warden.name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}
