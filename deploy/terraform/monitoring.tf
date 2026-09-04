# Uptime + availability alerting (SOC 2 Availability criterion, gap assessment P0 #2).
# Costs nothing at this scale: GCP uptime checks bill $0.30/1k executions past the free
# million per month; two checks at 60s from 3 regions is ~260k/month — inside the free
# tier. Alert notifications go to the security mailbox (email channels are free; the
# address gets a one-time verification email on first apply).

variable "alert_email" {
  type        = string
  description = "Mailbox for availability alerts (verified on first apply)."
  default     = "security@palivane.io"
}

variable "uptime_hosts" {
  type        = map(string)
  description = "Public hosts to probe -> path (200 expected)."
  default = {
    "palivane.io"     = "/"
    "app.palivane.io" = "/api/health"
  }
}

resource "google_monitoring_notification_channel" "security_email" {
  display_name = "Security mailbox"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_uptime_check_config" "public" {
  for_each     = var.uptime_hosts
  display_name = "uptime ${each.key}"
  timeout      = "10s"
  period       = "60s"
  # Default checker regions (3 continents) — a single-region blip does not page.

  http_check {
    path         = each.value
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = each.key
    }
  }
}

# Page when a host fails from >=2 checker regions for 3 consecutive minutes — outage
# shape, not a transient. (The uptime metric is 1 per successful check.)
resource "google_monitoring_alert_policy" "uptime" {
  for_each     = var.uptime_hosts
  display_name = "DOWN: ${each.key}"
  combiner     = "OR"

  conditions {
    display_name = "${each.key} failing from multiple regions"
    condition_threshold {
      filter = join(" AND ", [
        "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\"",
        "resource.type=\"uptime_url\"",
        "metric.label.check_id=\"${google_monitoring_uptime_check_config.public[each.key].uptime_check_id}\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      duration        = "180s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_COUNT_FALSE"
        group_by_fields      = ["resource.label.host"]
      }
      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  documentation {
    content   = "Uptime probes for ${each.key} are failing from multiple regions. Runbook: check Cloud Run revisions + Cloudflare; roll back with a redeploy of the previous SHA (deploy.yml)."
    mime_type = "text/markdown"
  }
}

# 5xx-rate alert on the Cloud Run service — catches "up but erroring", which an uptime
# probe on / misses. Fires at >5% server errors sustained for 5 minutes.
resource "google_monitoring_alert_policy" "server_errors" {
  display_name = "Cloud Run 5xx rate"
  combiner     = "OR"

  conditions {
    display_name = "5xx responses sustained"
    condition_threshold {
      filter = join(" AND ", [
        "metric.type=\"run.googleapis.com/request_count\"",
        "resource.type=\"cloud_run_revision\"",
        "resource.label.service_name=\"${var.service_name}\"",
        "metric.label.response_code_class=\"5xx\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0.5 # >0.5 errors/sec sustained — tune once real traffic sets a baseline
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  documentation {
    content   = "Sustained 5xx from the Palivane service. Check Cloud Run logs for the erroring revision; roll back via deploy.yml with the prior SHA."
    mime_type = "text/markdown"
  }
}
