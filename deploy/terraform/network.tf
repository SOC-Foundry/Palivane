# Custom-mode VPC. Cloud Run reaches Cloud SQL's PRIVATE IP over this network via Direct
# VPC egress (see cloudrun.tf); Cloud SQL's private IP is drawn from a private-services-
# access range peered to Google's service network.

resource "google_compute_network" "vpc" {
  name                    = "${var.service_name}-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  name                     = "${var.service_name}-subnet"
  ip_cidr_range            = var.subnet_cidr
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = false
}

# Reserved block for private-services-access (Cloud SQL private IP lives here).
resource "google_compute_global_address" "psa" {
  name          = var.psa_range_name
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.psa_prefix_length
  network       = google_compute_network.vpc.id
}

# Peer the VPC with Google's service network so managed services (Cloud SQL) get an IP
# from the reserved range above.
resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa.name]
}
