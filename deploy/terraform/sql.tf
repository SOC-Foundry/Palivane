# Cloud SQL Postgres 16, PRIVATE IP only (org policy forbids public IPs), with automated
# backups + point-in-time recovery. Reached from Cloud Run over the VPC peering above.

resource "google_sql_database_instance" "warden" {
  name             = "${var.service_name}-db"
  region           = var.region
  database_version = "POSTGRES_16"
  # Guard against an accidental `terraform destroy` wiping the database. This is the Cloud
  # SQL API's own flag, so it also blocks a console/gcloud delete — but it fails during
  # APPLY, i.e. partway through a run.
  deletion_protection = true

  # Second, earlier guard: fail at PLAN time on anything that would destroy OR replace this
  # instance. `name` is immutable, so editing var.service_name (e.g. a "rename to palivane"
  # sweep) plans a destroy+create — which is total data loss for every tenant. With this,
  # that plan is refused before a single resource is touched. Removing this line is a
  # deliberate, reviewable act; see docs/rebrand-batch-d-runbook.md item 4.
  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_service_networking_connection.psa]

  settings {
    tier                        = var.db_tier
    disk_size                   = var.db_disk_gb
    availability_type           = "ZONAL"
    enable_dataplex_integration = true

    ip_configuration {
      ipv4_enabled    = false # no public IP
      private_network = google_compute_network.vpc.id
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "08:00"
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 14
      }
    }
  }
}

resource "google_sql_database" "warden" {
  name     = "warden"
  instance = google_sql_database_instance.warden.name

  # The instance's deletion_protection does NOT cover the database inside it: dropping this
  # resource (or renaming it — `name` is immutable here too) deletes every table without
  # touching the instance. Same plan-time refusal.
  lifecycle {
    prevent_destroy = true
  }
}

# The DB password is provided out-of-band (var, not committed) and NOT emitted to any
# output. TF state will contain it — use a remote encrypted backend (see versions.tf).
variable "db_password" {
  type        = string
  sensitive   = true
  description = "Password for the warden Postgres user. Pass via TF_VAR_db_password or a secret tfvars; never commit it."
}

resource "google_sql_user" "warden" {
  name     = var.db_user
  instance = google_sql_database_instance.warden.name
  password = var.db_password
  # The API never returns the password, so TF would show a perpetual "update". The password
  # is owned out-of-band (the warden-database-url secret); don't let TF churn/rotate it.
  lifecycle {
    ignore_changes = [password]
  }
}
