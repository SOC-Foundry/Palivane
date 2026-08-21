terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30, < 7"
    }
  }
  backend "gcs" {} # partial: -backend-config="bucket=..." -backend-config="prefix=palivane-gke"
}

provider "google" {
  project = var.project_id
  region  = var.region
}
