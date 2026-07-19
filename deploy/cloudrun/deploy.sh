#!/usr/bin/env bash
# Build + deploy Warden to Cloud Run (single-origin: SPA + API), connected to Cloud SQL.
# Prereqs (once): see deploy/cloudrun/README.md — APIs enabled, Artifact Registry repo,
# a Cloud SQL Postgres instance, and Secret Manager secrets created.
#
#   PROJECT_ID=my-proj REGION=us-central1 \
#   SQL_CONNECTION=my-proj:us-central1:warden-db \
#   DOMAIN=app.warden.io \
#   ./deploy/cloudrun/deploy.sh
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-warden}"
REPO="${REPO:-warden}"
IMAGE_NAME="${IMAGE_NAME:-warden}"
: "${SQL_CONNECTION:?set SQL_CONNECTION (project:region:instance)}"
DOMAIN="${DOMAIN:-}"
TAG="$(git rev-parse --short HEAD 2>/dev/null || echo latest)"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${IMAGE_NAME}:${TAG}"

echo "==> Building & pushing $IMAGE"
gcloud builds submit --project "$PROJECT_ID" \
  --config deploy/cloudrun/cloudbuild.yaml \
  --substitutions "_REGION=${REGION},_REPO=${REPO},_IMAGE=${IMAGE_NAME},_TAG=${TAG}" .

# Non-secret runtime config. Secrets (DATABASE_URL, WARDEN_SECRET_KEY, provider keys) come
# from Secret Manager via --set-secrets below.
# "@"-separated (passed as ^@^...) so values may contain commas (e.g. WARDEN_ALLOWED_HOSTS).
ENV_VARS="GATEWAY_ENFORCE=${GATEWAY_ENFORCE:-true}"
ENV_VARS+="@GATEWAY_BLOCK_SEVERITY=${GATEWAY_BLOCK_SEVERITY:-high}"
ENV_VARS+="@GATEWAY_ANTHROPIC_BASE=${GATEWAY_ANTHROPIC_BASE:-https://api.anthropic.com}"
ENV_VARS+="@JUDGE_PROVIDER=${JUDGE_PROVIDER:-auto}"
# Judge model override (e.g. a Haiku-class model to keep per-verdict cost small).
[ -n "${JUDGE_MODEL:-}" ] && ENV_VARS+="@JUDGE_MODEL=${JUDGE_MODEL}"
# Public deploy: signup OFF by default (else the internet can self-register orgs). Set
# WARDEN_ALLOW_SIGNUP=true explicitly for an open multi-tenant deployment.
ENV_VARS+="@WARDEN_ALLOW_SIGNUP=${WARDEN_ALLOW_SIGNUP:-false}"
ENV_VARS+="@SEED_ON_START=${SEED_ON_START:-false}"
# WARDEN_ALLOWED_HOSTS may need more than DOMAIN (e.g. the *.run.app hostname when a
# fronting proxy/Worker reaches the service by its run.app origin) — allow an override.
[ -n "$DOMAIN" ] && ENV_VARS+="@CORS_ORIGINS=https://${DOMAIN}@WARDEN_PUBLIC_URL=https://${DOMAIN}@WARDEN_ALLOWED_HOSTS=${WARDEN_ALLOWED_HOSTS:-$DOMAIN}"
# Email plane (password reset / join verification / invites). SMTP_PASS rides in via the
# optional-secrets loop below (create secret 'warden-smtp-pass' to enable).
[ -n "${SMTP_HOST:-}" ] && ENV_VARS+="@SMTP_HOST=${SMTP_HOST}@SMTP_PORT=${SMTP_PORT:-587}@SMTP_USER=${SMTP_USER:-}@MAIL_FROM=${MAIL_FROM:-}"
# Encrypt stored finding content at rest (needs a durable WARDEN_SECRET_KEY — key loss =
# data loss). Opt-in per deploy; threaded through when set.
[ -n "${WARDEN_ENCRYPT_FINDINGS:-}" ] && ENV_VARS+="@WARDEN_ENCRYPT_FINDINGS=${WARDEN_ENCRYPT_FINDINGS}"
[ -n "${INGEST_TENANT:-}" ] && ENV_VARS+="@INGEST_TENANT=${INGEST_TENANT}"
[ -n "${WARDEN_EXTENSION_ID:-}" ] && ENV_VARS+="@WARDEN_EXTENSION_ID=${WARDEN_EXTENSION_ID}"

# Secrets — must exist in Secret Manager (see README). Optional ones are added if present.
SECRETS="WARDEN_SECRET_KEY=warden-secret-key:latest,DATABASE_URL=warden-database-url:latest"
for pair in \
  "GATEWAY_ANTHROPIC_KEY=gateway-anthropic-key" \
  "ANTHROPIC_API_KEY=judge-anthropic-key" \
  "OPENAI_API_KEY=openai-api-key" \
  "GEMINI_API_KEY=gemini-api-key" \
  "WARDEN_METRICS_TOKEN=warden-metrics-token" \
  "EXTENSION_INGEST_TOKEN=extension-ingest-token" \
  "SMTP_PASS=warden-smtp-pass"; do
  name="${pair##*=}"
  if gcloud secrets describe "$name" --project "$PROJECT_ID" >/dev/null 2>&1; then
    SECRETS+=",${pair}:latest"
  fi
done

# Direct VPC egress — required when Cloud SQL has a PRIVATE IP only (org policy
# constraints/sql.restrictPublicIp). Set VPC_NETWORK + VPC_SUBNET to route the Cloud SQL
# connector to the instance's private IP over the VPC.
VPC_ARGS=()
if [ -n "${VPC_NETWORK:-}" ] && [ -n "${VPC_SUBNET:-}" ]; then
  VPC_ARGS=(--network "$VPC_NETWORK" --subnet "$VPC_SUBNET" --vpc-egress "${VPC_EGRESS:-private-ranges-only}")
fi
# Public by default; on an org that forbids allUsers set INGRESS/NO_UNAUTH to lock it down.
AUTH_ARGS=(--allow-unauthenticated)
[ "${NO_UNAUTH:-}" = "1" ] && AUTH_ARGS=(--no-allow-unauthenticated)
[ -n "${INGRESS:-}" ] && AUTH_ARGS+=(--ingress "$INGRESS")

echo "==> Deploying Cloud Run service '$SERVICE'"
# --update-env-vars (merge), NOT --set-env-vars (replace): a deploy that omits a var must
# not silently drop it. Out-of-band config (e.g. SMTP set via `services update`) persists.
gcloud run deploy "$SERVICE" --project "$PROJECT_ID" --region "$REGION" \
  --image "$IMAGE" \
  --add-cloudsql-instances "$SQL_CONNECTION" \
  --update-env-vars "^@^${ENV_VARS}" \
  --set-secrets "$SECRETS" \
  "${AUTH_ARGS[@]}" \
  "${VPC_ARGS[@]}" \
  --port 8080 \
  --cpu 1 --memory 512Mi \
  --min-instances "${MIN_INSTANCES:-1}" --max-instances "${MAX_INSTANCES:-4}" \
  --cpu-boost --timeout 300

echo "==> Done. Service URL:"
gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" \
  --format 'value(status.url)'
[ -n "$DOMAIN" ] && echo "Map your domain: gcloud run domain-mappings create --service $SERVICE --domain $DOMAIN --region $REGION"
