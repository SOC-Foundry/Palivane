# Dedicated runtime identity for the Cloud Run service (least privilege — not the default
# compute SA). Note: the manually-provisioned prod uses the default compute SA; adopt this
# via `terraform import` or migrate the service to this SA (see README).
resource "google_service_account" "run" {
  account_id   = "${var.service_name}-run"
  display_name = "Warden Cloud Run runtime"
}

locals {
  run_roles = [
    "roles/cloudsql.client",
    "roles/secretmanager.secretAccessor",
    "roles/logging.logWriter",
  ]
}

resource "google_project_iam_member" "run" {
  for_each = toset(local.run_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.run.email}"
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
