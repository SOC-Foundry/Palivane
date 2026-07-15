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
  # Recommended: a remote GCS backend so state (which references secret resources, though
  # not their values) isn't kept locally. Fill in and uncomment.
  # backend "gcs" {
  #   bucket = "YOUR-TF-STATE-BUCKET"
  #   prefix = "warden"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
