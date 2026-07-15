# Secrets. WARDEN_SECRET_KEY and the metrics token are generated here and DATABASE_URL is
# composed from the SQL instance + db_password, so `apply` yields a working service. These
# values land in TF STATE — use the encrypted remote backend in versions.tf. The SMTP
# password is an external credential: its container is created here, but the value is added
# out-of-band (gcloud secrets versions add) so it never touches state.
#
# WARNING: WARDEN_SECRET_KEY encrypts findings at rest and signs sessions. Losing/rotating
# it = data loss + all sessions invalid. random_password keeps it stable in state; treat
# the state (and its backend) as sensitive.

resource "random_password" "secret_key" {
  length  = 48
  special = false
}

resource "random_password" "metrics_token" {
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "secret_key" {
  secret_id = "warden-secret-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}
resource "google_secret_manager_secret_version" "secret_key" {
  secret      = google_secret_manager_secret.secret_key.id
  secret_data = random_password.secret_key.result
}

resource "google_secret_manager_secret" "metrics_token" {
  secret_id = "warden-metrics-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}
resource "google_secret_manager_secret_version" "metrics_token" {
  secret      = google_secret_manager_secret.metrics_token.id
  secret_data = random_password.metrics_token.result
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "warden-database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}
resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.database_url.id
  # psycopg2 unix-socket form the app expects (host=/cloudsql/CONNECTION_NAME).
  secret_data = "postgresql+psycopg2://${var.db_user}:${var.db_password}@/warden?host=/cloudsql/${google_sql_database_instance.warden.connection_name}"
}

# Container only; add the value with:
#   printf '%s' 'APP_PASSWORD' | gcloud secrets versions add warden-smtp-pass --data-file=-
resource "google_secret_manager_secret" "smtp_pass" {
  secret_id = "warden-smtp-pass"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

# Let the runtime SA read each secret (in addition to the project-level accessor role).
resource "google_secret_manager_secret_iam_member" "run_access" {
  for_each = {
    sk = google_secret_manager_secret.secret_key.id
    mt = google_secret_manager_secret.metrics_token.id
    du = google_secret_manager_secret.database_url.id
    sp = google_secret_manager_secret.smtp_pass.id
  }
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}
