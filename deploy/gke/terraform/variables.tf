variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}

# Reuse the existing VPC (managed by deploy/terraform); looked up, not created here. Its
# private-services-access peering already lets Cloud SQL private IPs live in it.
variable "network_name" {
  type    = string
  default = "warden-vpc"
}

variable "gke_subnet_cidr" {
  type    = string
  default = "10.30.0.0/20"
}
variable "pods_cidr" {
  type    = string
  default = "10.32.0.0/14"
}
variable "services_cidr" {
  type    = string
  default = "10.36.0.0/20"
}

variable "cluster_name" {
  type    = string
  default = "warden"
}

# Enterprise customers that get a dedicated (node pool + Cloud SQL + GSA) single-tenant
# instance. Add an entry, apply, then run provision-customer.sh to install the app.
#   customers = { acme = { db_tier = "db-custom-1-3840" }, globex = {} }
variable "customers" {
  type = map(object({
    machine_type = optional(string, "e2-standard-2")
    min_nodes    = optional(number, 1)
    max_nodes    = optional(number, 3)
    db_tier      = optional(string, "db-g1-small")
    db_disk_gb   = optional(number, 10)
  }))
  default = {}
}
