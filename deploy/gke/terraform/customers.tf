# One dedicated, isolated stack per enterprise customer (see var.customers). Namespace and
# KSA follow a convention the provisioning script + Helm chart share: ns = <slug>,
# ksa = palivane-<slug>.
module "customer" {
  source   = "./modules/customer"
  for_each = var.customers

  customer      = each.key
  project_id    = var.project_id
  region        = var.region
  cluster_id    = google_container_cluster.warden.id
  network_id    = data.google_compute_network.vpc.id
  node_sa_email = google_service_account.nodes.email
  machine_type  = each.value.machine_type
  min_nodes     = each.value.min_nodes
  max_nodes     = each.value.max_nodes
  db_tier       = each.value.db_tier
  db_disk_gb    = each.value.db_disk_gb
  namespace     = each.key
  ksa_name      = "palivane-${each.key}"
}

output "customers" {
  description = "Per-customer GSA + Cloud SQL connection name for the provisioning script."
  value = {
    for k, m in module.customer : k => {
      gsa_email           = m.gsa_email
      sql_connection_name = m.sql_connection_name
    }
  }
}
