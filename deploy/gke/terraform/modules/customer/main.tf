# Everything that isolates ONE customer: a dedicated (tainted) node pool, a dedicated
# private Cloud SQL instance, and a Google SA the pod uses via Workload Identity.

# Dedicated node pool — tainted + labeled so only this customer's pods (which carry the
# matching toleration + nodeSelector, set by the Helm chart) land here.
resource "google_container_node_pool" "this" {
  name     = "cust-${var.customer}"
  cluster  = var.cluster_id
  location = var.region
  autoscaling {
    min_node_count = var.min_nodes
    max_node_count = var.max_nodes
  }
  node_config {
    machine_type    = var.machine_type
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    service_account = var.node_sa_email
    labels          = { warden-customer = var.customer }
    taint {
      key    = "dedicated"
      value  = var.customer
      effect = "NO_SCHEDULE"
    }
    workload_metadata_config { mode = "GKE_METADATA" }
  }
}

# Dedicated private Cloud SQL instance for this customer.
resource "google_sql_database_instance" "this" {
  name                = "warden-${var.customer}"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true
  settings {
    tier              = var.db_tier
    disk_size         = var.db_disk_gb
    availability_type = "ZONAL"
    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_id
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      backup_retention_settings { retained_backups = 14 }
    }
  }
}

resource "google_sql_database" "this" {
  name     = "warden"
  instance = google_sql_database_instance.this.name
}

# Per-pod Google SA: Cloud SQL client + secret access, bound to the customer's KSA.
resource "google_service_account" "app" {
  account_id   = "warden-${var.customer}"
  display_name = "Warden app (${var.customer})"
}
resource "google_project_iam_member" "cloudsql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.app.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${var.ksa_name}]"
}
