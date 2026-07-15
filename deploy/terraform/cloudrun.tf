locals {
  # Non-secret runtime env. Booleans render as "true"/"false" (config.py reads those).
  base_env = {
    GATEWAY_ENFORCE         = var.gateway_enforce ? "true" : "false"
    WARDEN_ALLOW_SIGNUP     = var.allow_signup ? "true" : "false"
    WARDEN_STORE_CONTENT    = var.store_content ? "true" : "false"
    WARDEN_ENCRYPT_FINDINGS = var.encrypt_findings ? "true" : "false"
  }
  domain_env = var.public_domain != "" ? {
    WARDEN_PUBLIC_URL = "https://${var.public_domain}"
    CORS_ORIGINS      = "https://${var.public_domain}"
  } : {}
  hosts_env = var.allowed_hosts != "" ? { WARDEN_ALLOWED_HOSTS = var.allowed_hosts } : {}
  ext_env   = var.extension_id != "" ? { WARDEN_EXTENSION_ID = var.extension_id } : {}
  smtp_env = var.smtp_host != "" ? {
    SMTP_HOST = var.smtp_host
    SMTP_USER = var.smtp_user
    MAIL_FROM = var.mail_from
  } : {}
  plain_env = merge(local.base_env, local.domain_env, local.hosts_env, local.ext_env, local.smtp_env)
}

resource "google_cloud_run_v2_service" "warden" {
  name     = var.service_name
  location = var.region
  # Public ingress, but invoker IAM (iam.tf) — NOT allUsers — decides who gets through.
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  depends_on = [
    google_secret_manager_secret_version.secret_key,
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_version.metrics_token,
    google_sql_database.warden,
  ]

  template {
    service_account                  = google_service_account.run.email
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    # Direct VPC egress — routes the Cloud SQL connector to the instance's private IP.
    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
    }

    # Cloud SQL unix socket at /cloudsql/<connection_name>.
    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.warden.connection_name]
      }
    }

    containers {
      image = var.image
      ports { container_port = 8080 }

      resources {
        limits            = { cpu = "1", memory = "512Mi" }
        cpu_idle          = true # scale CPU down between requests (matches min=0)
        startup_cpu_boost = true
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      dynamic "env" {
        for_each = local.plain_env
        content {
          name  = env.key
          value = env.value
        }
      }

      env {
        name = "WARDEN_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "WARDEN_METRICS_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.metrics_token.secret_id
            version = "latest"
          }
        }
      }
      # SMTP password only when SMTP is configured (else the secret has no version yet).
      dynamic "env" {
        for_each = var.smtp_host != "" ? [1] : []
        content {
          name = "SMTP_PASS"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.smtp_pass.secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  # CI/CD pushes new image tags out-of-band; don't let TF fight a newer deployed image.
  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }
}
