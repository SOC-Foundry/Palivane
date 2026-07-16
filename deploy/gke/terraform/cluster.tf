data "google_compute_network" "vpc" {
  name = var.network_name
}

# Dedicated subnet for the cluster with secondary ranges for pods + services.
resource "google_compute_subnetwork" "gke" {
  name                     = "${var.cluster_name}-gke-subnet"
  region                   = var.region
  network                  = data.google_compute_network.vpc.id
  ip_cidr_range            = var.gke_subnet_cidr
  private_ip_google_access = true
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

# GKE Standard (not Autopilot) — we need per-customer node pools with taints for isolation.
resource "google_container_cluster" "warden" {
  name     = var.cluster_name
  location = var.region

  network    = data.google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.gke.id

  # We manage node pools ourselves (one per customer); remove the default pool.
  remove_default_node_pool = true
  initial_node_count       = 1

  release_channel { channel = "REGULAR" }
  workload_identity_config { workload_pool = "${var.project_id}.svc.id.goog" }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # Private nodes; control plane reachable (lock down master_authorized_networks in prod).
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  deletion_protection = true
}

# A small shared/system pool so cluster-wide add-ons have somewhere to run that isn't a
# customer's dedicated (tainted) pool.
resource "google_container_node_pool" "system" {
  name     = "system"
  cluster  = google_container_cluster.warden.id
  location = var.region
  autoscaling {
    min_node_count = 1
    max_node_count = 2
  }
  node_config {
    machine_type    = "e2-small"
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    service_account = google_service_account.nodes.email
  }
}

# Least-privilege node identity (pods use Workload Identity for real access).
resource "google_service_account" "nodes" {
  account_id   = "${var.cluster_name}-gke-nodes"
  display_name = "Warden GKE nodes"
}
resource "google_project_iam_member" "nodes_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.nodes.email}"
}
resource "google_project_iam_member" "nodes_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.nodes.email}"
}
resource "google_project_iam_member" "nodes_artifacts" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.nodes.email}"
}
