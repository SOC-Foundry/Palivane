# MCP reputation dataset (mcp_reputation.json, ~12 MB). Built weekly by the mcp-dataset job
# in catalog-growth.yml and fetched into the image by deploy.sh; kept out of git because a
# fresh copy every week would bloat history. The dataset job writes it as the dataset SA and
# deploys read it as the release SA (service-accounts.tf); the runtime never reads it.
# Prod's bucket predates this resource and was imported into state on 2026-11-03 (#435,
# run 41569782525).
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
