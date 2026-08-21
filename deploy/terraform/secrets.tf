# Secrets. PALIVANE_SECRET_KEY and the metrics token are generated here and DATABASE_URL is
# composed from the SQL instance + db_password, so `apply` yields a working service. These
# values land in TF STATE — use the encrypted remote backend in versions.tf. The SMTP
# password is an external credential: its container is created here, but the value is added
# out-of-band (gcloud secrets versions add) so it never touches state.
#
# WARNING: PALIVANE_SECRET_KEY encrypts findings at rest and signs sessions. Losing/rotating
# it = data loss + all sessions invalid. random_password keeps it stable in state; treat
# the state (and its backend) as sensitive.

# Generated only for a fresh deploy. When adopting existing prod (adopt_existing=true) the
# secret VERSIONS below are skipped so TF never rotates the live values.
resource "random_password" "secret_key" {
  count   = var.adopt_existing ? 0 : 1
  length  = 48
  special = false
}

resource "random_password" "metrics_token" {
  count   = var.adopt_existing ? 0 : 1
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "secret_key" {
  secret_id = "palivane-secret-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}
resource "google_secret_manager_secret_version" "secret_key" {
  count       = var.adopt_existing ? 0 : 1
  secret      = google_secret_manager_secret.secret_key.id
  secret_data = random_password.secret_key[0].result
}

resource "google_secret_manager_secret" "metrics_token" {
  secret_id = "palivane-metrics-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}
resource "google_secret_manager_secret_version" "metrics_token" {
  count       = var.adopt_existing ? 0 : 1
  secret      = google_secret_manager_secret.metrics_token.id
  secret_data = random_password.metrics_token[0].result
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "palivane-database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}
resource "google_secret_manager_secret_version" "database_url" {
  count  = var.adopt_existing ? 0 : 1
  secret = google_secret_manager_secret.database_url.id
  # psycopg2 unix-socket form the app expects (host=/cloudsql/CONNECTION_NAME).
  secret_data = "postgresql+psycopg2://${var.db_user}:${var.db_password}@/palivane?host=/cloudsql/${google_sql_database_instance.palivane.connection_name}"
}

# Container only; add the value with:
#   printf '%s' 'APP_PASSWORD' | gcloud secrets versions add palivane-smtp-pass --data-file=-
resource "google_secret_manager_secret" "smtp_pass" {
  secret_id = "palivane-smtp-pass"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

# Grant the dedicated runtime SA read access to each secret. Skipped when adopting: the
# default compute SA already has project-level secretAccessor.
resource "google_secret_manager_secret_iam_member" "run_access" {
  for_each = var.adopt_existing ? {} : {
    sk = google_secret_manager_secret.secret_key.id
    mt = google_secret_manager_secret.metrics_token.id
    du = google_secret_manager_secret.database_url.id
    sp = google_secret_manager_secret.smtp_pass.id
  }
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.run_sa_email}"
}
