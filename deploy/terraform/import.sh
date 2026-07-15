#!/usr/bin/env bash
# Import the EXISTING (hand-built) production resources into Terraform state so a
# subsequent `plan` is a no-op and `apply` becomes safe to automate.
#
#   cd deploy/terraform
#   terraform init -backend-config="bucket=<STATE_BUCKET>" -backend-config="prefix=warden"
#   PROJECT_ID=erudite-calling-502022-k6 ./import.sh
#
# ─────────────────────────────────────────────────────────────────────────────────────
# READ FIRST — two parts of this config DIVERGE from prod. Importing without addressing
# them means the next `apply` would DESTROY/ROTATE live state. Edit the config before you
# import, or the plan afterward will be scary:
#
#  1. SECRET VALUES. secrets.tf GENERATES new values (random_password) and composes
#     DATABASE_URL. Prod's secrets already hold real values. If you let TF manage the
#     *versions*, apply creates NEW versions — rotating WARDEN_SECRET_KEY (=> findings become
#     undecryptable + all sessions invalid), the metrics token, and DATABASE_URL.
#     -> For adopting prod: in secrets.tf, comment out the three
#        `google_secret_manager_secret_version` resources and the two `random_password`
#        resources. Import only the secret CONTAINERS (done below). Leave the values alone.
#
#  2. RUNTIME SERVICE ACCOUNT. iam.tf/cloudrun.tf use a dedicated `warden-run` SA; prod runs
#     as the DEFAULT compute SA. Options:
#      (a) Keep the default compute SA: set template.service_account in cloudrun.tf to
#          "442729333907-compute@developer.gserviceaccount.com" and delete
#          google_service_account.run + google_project_iam_member.run + the run_access
#          bindings. Simplest; no migration.
#      (b) Migrate to warden-run (least privilege): leave the config, let apply CREATE the SA
#          and switch the service to it (a real, intended change — review it).
#
#  The SQL user password will always show as an in-place "update" (Terraform can't read it
#  back); with TF_DB_PASSWORD set to the CURRENT value it's a no-op in practice. Verify.
# ─────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
FRONT_SA="warden-front@${PROJECT_ID}.iam.gserviceaccount.com"

imp() { echo "==> $1"; terraform import "$1" "$2"; }

# APIs (enabling an already-enabled service is a no-op, but import avoids a spurious create)
for svc in run.googleapis.com sqladmin.googleapis.com secretmanager.googleapis.com \
           artifactregistry.googleapis.com compute.googleapis.com \
           servicenetworking.googleapis.com vpcaccess.googleapis.com; do
  imp "google_project_service.apis[\"${svc}\"]" "${PROJECT_ID}/${svc}"
done

# Network
imp google_compute_network.vpc         "projects/${PROJECT_ID}/global/networks/warden-vpc"
imp google_compute_subnetwork.subnet   "projects/${PROJECT_ID}/regions/${REGION}/subnetworks/warden-subnet"
imp google_compute_global_address.psa  "projects/${PROJECT_ID}/global/addresses/warden-psa"
imp google_service_networking_connection.psa \
    "projects/${PROJECT_ID}/global/networks/warden-vpc:servicenetworking.googleapis.com"

# Cloud SQL
imp google_sql_database_instance.warden "${PROJECT_ID}/warden-db"
imp google_sql_database.warden          "${PROJECT_ID}/warden-db/warden"
imp google_sql_user.warden              "${PROJECT_ID}/warden-db/warden"

# Artifact Registry
imp google_artifact_registry_repository.warden \
    "projects/${PROJECT_ID}/locations/${REGION}/repositories/warden"

# Secret CONTAINERS only (NOT versions — see note #1 above)
imp google_secret_manager_secret.secret_key    "projects/${PROJECT_ID}/secrets/warden-secret-key"
imp google_secret_manager_secret.metrics_token "projects/${PROJECT_ID}/secrets/warden-metrics-token"
imp google_secret_manager_secret.database_url  "projects/${PROJECT_ID}/secrets/warden-database-url"
imp google_secret_manager_secret.smtp_pass     "projects/${PROJECT_ID}/secrets/warden-smtp-pass"

# Cloudflare Worker front-door SA (exists); the runtime SA is handled per note #2.
imp google_service_account.front \
    "projects/${PROJECT_ID}/serviceAccounts/${FRONT_SA}"

# Cloud Run service + the Worker's invoker binding
imp google_cloud_run_v2_service.warden "projects/${PROJECT_ID}/locations/${REGION}/services/warden"
imp google_cloud_run_v2_service_iam_member.invoker_front \
    "projects/${PROJECT_ID}/locations/${REGION}/services/warden roles/run.invoker serviceAccount:${FRONT_SA}"

# Human-user invokers, if you set var.invoker_members to include them — one per member, e.g.:
#   imp 'google_cloud_run_v2_service_iam_member.invokers["user:davidk@tachtech.net"]' \
#       "projects/${PROJECT_ID}/locations/${REGION}/services/warden roles/run.invoker user:davidk@tachtech.net"

cat <<DONE

Imported. NOW:
  terraform plan
Review it carefully. A clean adoption shows NO destroys and NO secret-version creates.
The only expected "changes" are benign (e.g. the SQL user password update TF can't avoid,
labels/annotations). DO NOT apply until the plan matches your intent.
DONE
