#!/usr/bin/env bash
# Import the EXISTING (hand-built) production resources into Terraform state so a
# subsequent `plan` is a no-op and `apply` becomes safe to automate.
#
#   cd deploy/terraform
#   terraform init -backend-config="bucket=<STATE_BUCKET>" -backend-config="prefix=palivane"
#   PROJECT_ID=<the-hand-built-project> ./import.sh
#
# NOT for the `palivane` environment — that was provisioned by this config from empty and
# is already fully in state; importing it would be a no-op at best.
#
# ─────────────────────────────────────────────────────────────────────────────────────
# Run with adopt_existing=true (a tfvars line or -var) for every plan/apply against prod:
#     echo 'adopt_existing = true' >> terraform.tfvars
# That flag makes the config prod-safe automatically — it skips generating the secret
# VERSIONS (so prod's real PALIVANE_SECRET_KEY / DATABASE_URL / metrics values are untouched)
# and runs the service as the default compute SA instead of creating palivane-run. No manual
# editing needed.
#
# The SQL user password may still show as an in-place "update" (Terraform can't read it
# back); with TF_DB_PASSWORD set to the CURRENT value that's a no-op in practice. Verify.
# ─────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
FRONT_SA="palivane-front@${PROJECT_ID}.iam.gserviceaccount.com"

imp() { echo "==> $1"; terraform import "$1" "$2"; }

# APIs (enabling an already-enabled service is a no-op, but import avoids a spurious create)
for svc in run.googleapis.com sqladmin.googleapis.com secretmanager.googleapis.com \
           artifactregistry.googleapis.com compute.googleapis.com \
           servicenetworking.googleapis.com vpcaccess.googleapis.com; do
  imp "google_project_service.apis[\"${svc}\"]" "${PROJECT_ID}/${svc}"
done

# Network
imp google_compute_network.vpc         "projects/${PROJECT_ID}/global/networks/palivane-vpc"
imp google_compute_subnetwork.subnet   "projects/${PROJECT_ID}/regions/${REGION}/subnetworks/palivane-subnet"
imp google_compute_global_address.psa  "projects/${PROJECT_ID}/global/addresses/palivane-psa"
imp google_service_networking_connection.psa \
    "projects/${PROJECT_ID}/global/networks/palivane-vpc:servicenetworking.googleapis.com"

# Cloud SQL
imp google_sql_database_instance.palivane "${PROJECT_ID}/palivane-db"
imp google_sql_database.palivane          "${PROJECT_ID}/palivane-db/palivane"
imp google_sql_user.palivane              "${PROJECT_ID}/palivane-db/palivane"

# Artifact Registry
imp google_artifact_registry_repository.palivane \
    "projects/${PROJECT_ID}/locations/${REGION}/repositories/palivane"

# Secret CONTAINERS only (NOT versions — see note #1 above)
imp google_secret_manager_secret.secret_key    "projects/${PROJECT_ID}/secrets/palivane-secret-key"
imp google_secret_manager_secret.metrics_token "projects/${PROJECT_ID}/secrets/palivane-metrics-token"
imp google_secret_manager_secret.database_url  "projects/${PROJECT_ID}/secrets/palivane-database-url"
imp google_secret_manager_secret.smtp_pass     "projects/${PROJECT_ID}/secrets/palivane-smtp-pass"

# Cloudflare Worker front-door SA (exists); the runtime SA is handled per note #2.
imp google_service_account.front \
    "projects/${PROJECT_ID}/serviceAccounts/${FRONT_SA}"

# Cloud Run service + the Worker's invoker binding
imp google_cloud_run_v2_service.palivane "projects/${PROJECT_ID}/locations/${REGION}/services/palivane"
imp google_cloud_run_v2_service_iam_member.invoker_front \
    "projects/${PROJECT_ID}/locations/${REGION}/services/palivane roles/run.invoker serviceAccount:${FRONT_SA}"

# Human-user invokers, if you set var.invoker_members to include them — one per member, e.g.:
#   imp 'google_cloud_run_v2_service_iam_member.invokers["user:davidk@palivane.io"]' \
#       "projects/${PROJECT_ID}/locations/${REGION}/services/palivane roles/run.invoker user:davidk@palivane.io"

cat <<DONE

Imported. NOW (with adopt_existing = true set):
  terraform plan
A clean adoption shows NO destroys and NO secret-version creates. The only expected
"changes" are benign (e.g. the SQL user password update TF can't avoid, labels). DO NOT
apply until the plan matches your intent.
DONE
