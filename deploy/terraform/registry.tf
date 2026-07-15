resource "google_artifact_registry_repository" "warden" {
  location      = var.region
  repository_id = var.service_name
  format        = "DOCKER"
  description   = "Warden container images"
  depends_on    = [google_project_service.apis]
}
