#!/usr/bin/env bash
# One-time setup of keyless GitHub Actions -> GCP auth (Workload Identity Federation) for
# the CI/CD workflows in .github/workflows. Creates a deploy service account, a WIF pool +
# GitHub OIDC provider (locked to THIS repo), the Terraform state bucket, and prints the
# values to paste into GitHub (Settings -> Secrets and variables -> Actions).
#
#   PROJECT_ID=palivane REPO=SOC-Foundry/Palivane ./deploy/gcp/setup-wif.sh
#
# HIGH PRIVILEGE: the deploy SA gets project-admin-level roles so Terraform can manage the
# stack. The WIF provider is restricted to `attribute.repository == <REPO>`, so only Actions
# runs from this exact repository can impersonate it. Review the role list before running.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REPO="${REPO:?set REPO (e.g. owner/name)}"
REGION="${REGION:-us-central1}"
POOL="${POOL:-github-pool}"
PROVIDER="${PROVIDER:-github-provider}"
SA_NAME="${SA_NAME:-palivane-deploy}"
STATE_BUCKET="${STATE_BUCKET:-${PROJECT_ID}-tfstate}"

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"

echo "==> Enabling APIs (iam, sts, iamcredentials)"
gcloud services enable iam.googleapis.com sts.googleapis.com iamcredentials.googleapis.com \
  --project "$PROJECT_ID"

echo "==> Deploy service account: $SA_EMAIL"
gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT_ID" \
  --display-name "Palivane CI/CD deploy" 2>/dev/null || echo "  (already exists)"

# Newly-created SAs take a few seconds to be usable in IAM bindings — wait for propagation.
echo "  waiting for the SA to propagate..."
for _ in $(seq 1 20); do
  gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1 && break
  sleep 3
done

echo "==> Granting roles to the deploy SA"
# Split note: deploy.yml (app rollout) needs only the first four; the rest are for
# terraform-apply.yml (full infra). Splitting into two SAs is the hardening step later.
ROLES=(
  roles/run.admin
  roles/cloudbuild.builds.editor
  roles/artifactregistry.writer
  roles/iam.serviceAccountUser
  roles/storage.admin
  roles/cloudsql.admin
  roles/compute.networkAdmin
  roles/servicenetworking.networksAdmin
  roles/secretmanager.admin
  roles/iam.serviceAccountAdmin
  roles/resourcemanager.projectIamAdmin
  roles/serviceusage.serviceUsageAdmin
)
for role in "${ROLES[@]}"; do
  for attempt in 1 2 3 4 5; do
    if gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member "serviceAccount:${SA_EMAIL}" --role "$role" --condition=None >/dev/null 2>&1; then
      echo "  + $role"; break
    fi
    [ "$attempt" = 5 ] && { echo "  ! failed to bind $role"; exit 1; }
    sleep 4
  done
done

echo "==> Terraform state bucket: gs://${STATE_BUCKET}"
gcloud storage buckets create "gs://${STATE_BUCKET}" --project "$PROJECT_ID" \
  --location "$REGION" --uniform-bucket-level-access 2>/dev/null || echo "  (already exists)"
gcloud storage buckets update "gs://${STATE_BUCKET}" --versioning >/dev/null

echo "==> Workload Identity pool + GitHub OIDC provider"
gcloud iam workload-identity-pools create "$POOL" --project "$PROJECT_ID" \
  --location global --display-name "GitHub Actions" 2>/dev/null || echo "  (pool exists)"
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
  --project "$PROJECT_ID" --location global --workload-identity-pool "$POOL" \
  --display-name "GitHub" \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition "assertion.repository=='${REPO}'" 2>/dev/null || echo "  (provider exists)"

echo "==> Letting Actions runs from ${REPO} impersonate the deploy SA"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" --project "$PROJECT_ID" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/attribute.repository/${REPO}" >/dev/null

PROVIDER_RESOURCE="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"

cat <<DONE

==============================================================================
Done. Set these in GitHub (Settings -> Secrets and variables -> Actions):

  Repository VARIABLES:
    GCP_WORKLOAD_IDENTITY_PROVIDER = ${PROVIDER_RESOURCE}
    GCP_DEPLOY_SA                  = ${SA_EMAIL}
    GCP_PROJECT_ID                 = ${PROJECT_ID}
    GCP_REGION                     = ${REGION}
    TF_STATE_BUCKET                = ${STATE_BUCKET}
    GCP_SQL_CONNECTION             = ${PROJECT_ID}:${REGION}:palivane-db
    VPC_NETWORK                    = palivane-vpc
    VPC_SUBNET                     = palivane-subnet
    DOMAIN, PALIVANE_ALLOWED_HOSTS, PALIVANE_EXTENSION_ID, GATEWAY_ENFORCE,
    PALIVANE_ALLOW_SIGNUP, PALIVANE_ENCRYPT_FINDINGS, SMTP_HOST, SMTP_USER, MAIL_FROM
                                   = (match your current deploy command)

  Repository SECRETS:
    TF_DB_PASSWORD                 = (the palivane Postgres user password)

  Environments: create 'production' and 'production-infra' with required reviewers.

To restrict deploys to the main branch only, tighten the SA binding to
  .../attribute.repository_ref/${REPO}:refs/heads/main   (see docs).
==============================================================================
DONE
