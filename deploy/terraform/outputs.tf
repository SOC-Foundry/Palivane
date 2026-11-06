output "service_url" {
  value       = google_cloud_run_v2_service.palivane.uri
  description = "The Cloud Run service URL (behind invoker IAM / the Cloudflare Worker)."
}

output "sql_connection_name" {
  value       = google_sql_database_instance.palivane.connection_name
  description = "Cloud SQL connection name (project:region:instance)."
}

output "runtime_service_account" {
  value = local.run_sa_email
}

output "front_service_account" {
  value       = google_service_account.front.email
  description = "Grant this to the Cloudflare Worker (deploy/cloudflare) as its GCP_SA_KEY identity."
}

output "artifact_registry" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.palivane.repository_id}"
}

output "mcp_reputation_bucket" {
  value       = google_storage_bucket.mcp_reputation.name
  description = "Set as the MCP_REPUTATION_BUCKET repo variable (catalog-growth.yml uploads, deploy.sh fetches)."
}

# The release signing key; its imported version N is what RELEASE_KMS_KEY_VERSION names:
# <this>/cryptoKeyVersions/N.
output "release_signing_key" {
  value = google_kms_crypto_key.release.id
}
