#!/usr/bin/env bash
# Build + deploy Palivane to Cloud Run (single-origin: SPA + API), connected to Cloud SQL.
# Prereqs (once): see deploy/cloudrun/README.md — APIs enabled, Artifact Registry repo,
# a Cloud SQL Postgres instance, and Secret Manager secrets created.
#
#   PROJECT_ID=my-proj REGION=us-central1 \
#   SQL_CONNECTION=my-proj:us-central1:palivane-db \
#   DOMAIN=app.palivane.io \
#   ./deploy/cloudrun/deploy.sh
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-palivane}"
REPO="${REPO:-palivane}"
IMAGE_NAME="${IMAGE_NAME:-palivane}"
: "${SQL_CONNECTION:?set SQL_CONNECTION (project:region:instance)}"
DOMAIN="${DOMAIN:-}"
TAG="$(git rev-parse --short HEAD 2>/dev/null || echo latest)"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${IMAGE_NAME}:${TAG}"

echo "==> Building & pushing $IMAGE"
gcloud builds submit --project "$PROJECT_ID" \
  --config deploy/cloudrun/cloudbuild.yaml \
  --suppress-logs \
  --substitutions "_REGION=${REGION},_REPO=${REPO},_IMAGE=${IMAGE_NAME},_TAG=${TAG},_SELF_HOSTED=${PALIVANE_SELF_HOSTED:-}" .

# Non-secret runtime config. Secrets (DATABASE_URL, PALIVANE_SECRET_KEY, provider keys) come
# from Secret Manager via --set-secrets below.
# "|"-separated (passed as ^|^...) so values may contain commas (PALIVANE_ALLOWED_HOSTS) AND
# "@" (SMTP_USER/MAIL_FROM email addresses). "|" appears in none of the values.
ENV_VARS="GATEWAY_ENFORCE=${GATEWAY_ENFORCE:-true}"
# Build identity (the image tag = git short sha). Served at /cli/manifest.json so devices
# can tell whether their installed hooks/addon are current, and shown in the Fleet view.
ENV_VARS+="|PALIVANE_VERSION=${TAG}"
ENV_VARS+="|GATEWAY_BLOCK_SEVERITY=${GATEWAY_BLOCK_SEVERITY:-high}"
ENV_VARS+="|GATEWAY_ANTHROPIC_BASE=${GATEWAY_ANTHROPIC_BASE:-https://api.anthropic.com}"
ENV_VARS+="|JUDGE_PROVIDER=${JUDGE_PROVIDER:-auto}"
# Judge model override (e.g. a Haiku-class model to keep per-verdict cost small).
[ -n "${JUDGE_MODEL:-}" ] && ENV_VARS+="|JUDGE_MODEL=${JUDGE_MODEL}"
# Judge plan gating (SaaS: the operator-funded judge is an Enterprise entitlement).
[ -n "${PALIVANE_JUDGE_PLAN_GATED:-}" ] && ENV_VARS+="|PALIVANE_JUDGE_PLAN_GATED=${PALIVANE_JUDGE_PLAN_GATED}"
# Public deploy: signup OFF by default (else the internet can self-register orgs). Set
# PALIVANE_ALLOW_SIGNUP=true explicitly for an open multi-tenant deployment.
ENV_VARS+="|PALIVANE_ALLOW_SIGNUP=${PALIVANE_ALLOW_SIGNUP:-false}"
ENV_VARS+="|SEED_ON_START=${SEED_ON_START:-false}"
# PALIVANE_ALLOWED_HOSTS may need more than DOMAIN (e.g. the *.run.app hostname when a
# fronting proxy/Worker reaches the service by its run.app origin) — allow an override.
[ -n "$DOMAIN" ] && ENV_VARS+="|CORS_ORIGINS=https://${DOMAIN}|PALIVANE_PUBLIC_URL=https://${DOMAIN}|PALIVANE_ALLOWED_HOSTS=${PALIVANE_ALLOWED_HOSTS:-$DOMAIN}"
# Email plane (password reset / join verification / invites). Two transports: SMTP
# (SMTP_PASS rides in via the optional-secrets loop below — create 'palivane-smtp-pass')
# or the Cloudflare Email Service REST API (token via 'palivane-cf-email-token', account
# id here — it is not a secret). MAIL_FROM is shared by both, so it is threaded
# independently of which transport is configured.
[ -n "${SMTP_HOST:-}" ] && ENV_VARS+="|SMTP_HOST=${SMTP_HOST}|SMTP_PORT=${SMTP_PORT:-587}|SMTP_USER=${SMTP_USER:-}"
[ -n "${CF_EMAIL_ACCOUNT_ID:-}" ] && ENV_VARS+="|CF_EMAIL_ACCOUNT_ID=${CF_EMAIL_ACCOUNT_ID}"
[ -n "${MAIL_FROM:-}" ] && ENV_VARS+="|MAIL_FROM=${MAIL_FROM}"
# MCP reputation feed (opt-in): point at the shipped starter dataset
# (/app/data/mcp-reputation-starter.json) or a licensed one.
[ -n "${PALIVANE_MCP_REPUTATION_FEED:-}" ] && ENV_VARS+="|MCP_REPUTATION_FEED=${PALIVANE_MCP_REPUTATION_FEED}"
# Public read-only demo — slug of the seeded demo tenant (run `python -m app.seed`
# against prod once, with a random SEED_ADMIN_PASSWORD). Empty = no demo button.
[ -n "${PALIVANE_DEMO_ORG:-}" ] && ENV_VARS+="|PALIVANE_DEMO_ORG=${PALIVANE_DEMO_ORG}"
# "Continue with Google" (app-global social sign-in). The client id is not a secret;
# the client secret rides in via the optional-secrets loop (palivane-google-oauth-secret).
[ -n "${GOOGLE_OAUTH_CLIENT_ID:-}" ] && ENV_VARS+="|GOOGLE_OAUTH_CLIENT_ID=${GOOGLE_OAUTH_CLIENT_ID}"
# Self-serve billing (Stripe Checkout for Team). Price ids are not secrets; the API key
# and webhook signing secret ride in via the optional-secrets loop below (create
# 'palivane-stripe-secret-key' + 'palivane-stripe-webhook-secret' to enable).
[ -n "${STRIPE_PUBLISHABLE_KEY:-}" ] && ENV_VARS+="|STRIPE_PUBLISHABLE_KEY=${STRIPE_PUBLISHABLE_KEY}"
[ -n "${STRIPE_PRICE_TEAM_MONTHLY:-}" ] && ENV_VARS+="|STRIPE_PRICE_TEAM_MONTHLY=${STRIPE_PRICE_TEAM_MONTHLY}"
[ -n "${STRIPE_PRICE_TEAM_ANNUAL:-}" ] && ENV_VARS+="|STRIPE_PRICE_TEAM_ANNUAL=${STRIPE_PRICE_TEAM_ANNUAL}"
# Encrypt stored finding content at rest (needs a durable PALIVANE_SECRET_KEY — key loss =
# data loss). Opt-in per deploy; threaded through when set.
[ -n "${PALIVANE_ENCRYPT_FINDINGS:-}" ] && ENV_VARS+="|PALIVANE_ENCRYPT_FINDINGS=${PALIVANE_ENCRYPT_FINDINGS}"
[ -n "${INGEST_TENANT:-}" ] && ENV_VARS+="|INGEST_TENANT=${INGEST_TENANT}"
[ -n "${PALIVANE_EXTENSION_ID:-}" ] && ENV_VARS+="|PALIVANE_EXTENSION_ID=${PALIVANE_EXTENSION_ID}"
# Role-based S3 delivery: this deployment's AWS identity. The WIF role is assumed with
# the runtime's GCP identity token (no stored AWS secret); the principal is what customer
# trust policies name (usually the same role ARN).
[ -n "${PALIVANE_AWS_WIF_ROLE_ARN:-}" ] && ENV_VARS+="|PALIVANE_AWS_WIF_ROLE_ARN=${PALIVANE_AWS_WIF_ROLE_ARN}"
[ -n "${PALIVANE_AWS_DELIVERY_PRINCIPAL:-}" ] && ENV_VARS+="|PALIVANE_AWS_DELIVERY_PRINCIPAL=${PALIVANE_AWS_DELIVERY_PRINCIPAL}"
# Published Slack app ("Add to Slack" install for message scanning). Client id is not a
# secret; the client secret rides in via the optional-secrets loop below (create secret
# 'palivane-slack-client-secret' to enable). Redirect override for proxied deployments.
[ -n "${PALIVANE_SLACK_CLIENT_ID:-}" ] && ENV_VARS+="|PALIVANE_SLACK_CLIENT_ID=${PALIVANE_SLACK_CLIENT_ID}"
[ -n "${PALIVANE_SLACK_REDIRECT_URL:-}" ] && ENV_VARS+="|PALIVANE_SLACK_REDIRECT_URL=${PALIVANE_SLACK_REDIRECT_URL}"

# Secrets — must exist in Secret Manager (see README). Optional ones are added if present.
SECRETS="PALIVANE_SECRET_KEY=palivane-secret-key:latest,DATABASE_URL=palivane-database-url:latest"
for pair in \
  "GATEWAY_ANTHROPIC_KEY=gateway-anthropic-key" \
  "ANTHROPIC_API_KEY=judge-anthropic-key" \
  "OPENAI_API_KEY=openai-api-key" \
  "GEMINI_API_KEY=gemini-api-key" \
  "PALIVANE_METRICS_TOKEN=palivane-metrics-token" \
  "EXTENSION_INGEST_TOKEN=extension-ingest-token" \
  "SMTP_PASS=palivane-smtp-pass" \
  "CF_EMAIL_TOKEN=palivane-cf-email-token" \
  "GOOGLE_OAUTH_CLIENT_SECRET=palivane-google-oauth-secret" \
  "STRIPE_SECRET_KEY=palivane-stripe-secret-key" \
  "STRIPE_WEBHOOK_SECRET=palivane-stripe-webhook-secret" \
  "PALIVANE_LICENSE_SIGNING_KEY=palivane-license-signing-key" \
  "PALIVANE_RELEASE_SIGNING_KEY=palivane-release-signing-key" \
  "PALIVANE_SLACK_CLIENT_SECRET=palivane-slack-client-secret"; do
  name="${pair##*=}"
  # Require an ENABLED VERSION, not merely that the secret exists. Terraform creates
  # palivane-smtp-pass deliberately empty (the value is added out of band), so a
  # describe-only check wires up ":latest" for a secret that has nothing to resolve to,
  # and Cloud Run rejects the whole revision:
  #   spec...secret_key_ref.name: Secret projects/N/secrets/palivane-smtp-pass ... 
  # That failed every full deploy while an image-only `gcloud run deploy` kept working,
  # because the latter reuses the existing revision's config instead of rebuilding it.
  if gcloud secrets versions list "$name" --project "$PROJECT_ID" \
       --filter "state=ENABLED" --format "value(name)" --limit 1 2>/dev/null | grep -q .; then
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
  --update-env-vars "^|^${ENV_VARS}" \
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
# An `[ cond ] && cmd` as the FINAL statement takes the test's exit status when the
# condition is false, so with DOMAIN unset this script reported failure after a deploy
# that had already succeeded. Written as an if so the script's status reflects the
# deploy, not whether an optional hint happened to print.
if [ -n "$DOMAIN" ]; then
  echo "Map your domain: gcloud run domain-mappings create --service $SERVICE --domain $DOMAIN --region $REGION"
fi
