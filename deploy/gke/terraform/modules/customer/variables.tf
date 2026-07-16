variable "customer" { type = string }
variable "project_id" { type = string }
variable "region" { type = string }
variable "cluster_id" { type = string }
variable "network_id" { type = string }
variable "node_sa_email" { type = string }
variable "machine_type" { type = string }
variable "min_nodes" { type = number }
variable "max_nodes" { type = number }
variable "db_tier" { type = string }
variable "db_disk_gb" { type = number }
# Namespace + KSA the app runs under (Workload Identity binds the GSA to this).
variable "namespace" { type = string }
variable "ksa_name" { type = string }
