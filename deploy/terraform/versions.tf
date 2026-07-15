terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30, < 7"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
  # Remote state (encrypted at rest by GCS). Partial config: CI passes the bucket via
  #   terraform init -backend-config="bucket=...  -backend-config="prefix=warden"
  # and local validate uses `terraform init -backend=false`.
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}
