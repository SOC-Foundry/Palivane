# Palivane on GKE — per-customer isolation

For enterprise customers that require **hard tenant isolation**, Palivane runs a dedicated,
single-tenant instance per customer on a shared GKE Standard cluster. This is the isolated
tier alongside the multi-tenant Cloud Run SaaS (`deploy/cloudrun`, `deploy/terraform`) —
same container image, isolated infrastructure.

## What "isolated" means here

Each customer gets:

| Boundary | Mechanism |
|----------|-----------|
| Compute | Dedicated **node pool**, tainted `dedicated=<slug>:NoSchedule` + labeled `palivane-customer=<slug>`. Only that customer's pods tolerate the taint, so no other tenant's workload ever lands on their nodes. |
| Data | Dedicated **Cloud SQL** instance (private IP, own backups + PITR). No shared database. |
| Identity | Dedicated **Google service account** (`palivane-<slug>`) with only `cloudsql.client` + `secretmanager.secretAccessor`, bound to the pod's KSA via **Workload Identity**. |
| Network | Own **namespace**, own **subdomain** + Google-managed TLS cert, container-native LB (NEG). |
| Secrets | Own `PALIVANE_SECRET_KEY` (per-instance encryption root) + DB URL in Secret Manager. |

The shared cluster itself only hosts a small `system` node pool for add-ons; customer
workloads never run on it.

## Layout

- `terraform/` — the cluster (`cluster.tf`) + a reusable per-customer module
  (`modules/customer/`) instantiated once per entry in the `customers` map (`customers.tf`).
- `chart/palivane/` — Helm chart for one single-tenant instance (Deployment with Cloud SQL
  proxy sidecar, Service+NEG, Ingress+ManagedCertificate, Workload-Identity ServiceAccount).
- `provision-customer.sh` — end-to-end onboarding for one customer.

## First-time cluster setup

```sh
cd terraform
cp customers.auto.tfvars.example customers.auto.tfvars   # edit project/region
terraform init -backend-config="bucket=<tf-state-bucket>"
terraform apply                                          # creates cluster + system pool
```

Reuses the existing `palivane-vpc` (with PSA peering already established for private Cloud
SQL); it creates its own `palivane-gke-subnet` with secondary ranges for pods/services.

## Onboard a customer

```sh
# 1. add the customer to terraform/customers.auto.tfvars, e.g.
#      customers = { acme = { machine_type = "e2-standard-2", min_nodes = 1,
#                             max_nodes = 3, db_tier = "db-g1-small", db_disk_gb = 10 } }
# 2. run:
./provision-customer.sh acme acme.app.palivane.io
```

The script applies the customer's Terraform (node pool + Cloud SQL + GSA), creates the
namespace + secrets (idempotent — never rotates an existing key), and `helm upgrade
--install`s the instance. It prints the DNS + first-admin steps to finish.

## Notes

- **GKE Standard, not Autopilot** — Autopilot doesn't allow the dedicated tainted node
  pools this isolation model depends on.
- Nothing here is applied automatically by CI; cluster + customer creation is a deliberate,
  cost-bearing operator action.
- Deletion protection is on for the cluster and every customer Cloud SQL instance. To
  offboard, remove the customer from the map and `terraform apply` after clearing protection.
