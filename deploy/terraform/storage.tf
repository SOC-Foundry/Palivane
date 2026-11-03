# MCP reputation dataset (mcp_reputation.json, ~12 MB). Built weekly by the mcp-dataset job
# in catalog-growth.yml and fetched into the image by deploy.sh; kept out of git because a
# fresh copy every week would bloat history. Both sides run as the deploy SA, which already
# holds roles/storage.admin, and the runtime never reads the bucket, so no IAM here.
# catalog-growth.yml creates this same bucket if it is missing, so prod's bucket predates
# this resource: the import blocks below adopt it (and the already-enabled storage API).
# Versioned, so a bad week can be rolled back by restoring the previous generation.
resource "google_storage_bucket" "mcp_reputation" {
  name                        = "${var.project_id}-mcp-reputation"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # Keep a quarter of noncurrent weekly generations, not all of them.
  lifecycle_rule {
    condition {
      num_newer_versions = 12
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.apis]
}

# Adopt what already exists in prod instead of creating it. Delete these two blocks once an
# apply has run with them (a no-op from then on); a fresh environment without the bucket
# must drop them before its first plan, since an import of a missing object fails.
import {
  to = google_storage_bucket.mcp_reputation
  id = "${var.project_id}-mcp-reputation"
}

import {
  to = google_project_service.apis["storage.googleapis.com"]
  id = "${var.project_id}/storage.googleapis.com"
}
