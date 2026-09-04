# Application-error alerting (gap-assessment item 10): Cloud Run tracebacks land in Cloud
# Logging with severity>=ERROR; a log-based metric + alert turns "errors are happening"
# into a page instead of something discovered while debugging a customer report. Free at
# this scale (log-based metrics and email channels have no charge; log volume is already
# being ingested).

resource "google_logging_metric" "app_errors" {
  name   = "palivane-app-errors"
  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\" AND severity>=ERROR"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "app_errors" {
  display_name = "Application errors (Cloud Run logs)"
  combiner     = "OR"

  conditions {
    display_name = "error-level log entries sustained"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.app_errors.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 5 # >5 error lines/min sustained 5 min — tune with real baseline
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  documentation {
    content   = "Sustained error-level logs from the Palivane service. Read the erroring revision's logs (Cloud Run -> Logs, filter severity>=ERROR); if a fresh deploy caused it, roll back via deploy.yml with the prior SHA."
    mime_type = "text/markdown"
  }
}
