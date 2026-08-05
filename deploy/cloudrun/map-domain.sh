#!/usr/bin/env bash
# Map a custom domain to the Warden Cloud Run service (auto-provisions a managed TLS cert).
# Prereqs: the service is deployed (deploy.sh), you own the domain, and you've verified
# ownership once (Search Console) — see the steps this script prints.
#
#   PROJECT_ID=my-proj REGION=us-central1 DOMAIN=app.warden.io ./deploy/cloudrun/map-domain.sh
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-warden}"
: "${DOMAIN:?set DOMAIN (e.g. app.warden.io)}"

cat <<NOTE
Before mapping, the domain must be verified to your account (one-time):
  1) gcloud domains verify ${DOMAIN#*.}        # opens Search Console; add the TXT record it gives
  2) confirm it shows under: gcloud domains list-user-verified
Then this script creates the mapping and prints the DNS records to add at your registrar.
NOTE

echo "==> Creating domain mapping ${DOMAIN} -> ${SERVICE} (${REGION})"
gcloud beta run domain-mappings create --project "$PROJECT_ID" --region "$REGION" \
  --service "$SERVICE" --domain "$DOMAIN"

echo
echo "==> Add these DNS records at your registrar (rrdata is the target):"
gcloud beta run domain-mappings describe --project "$PROJECT_ID" --region "$REGION" \
  --domain "$DOMAIN" \
  --format='table(status.resourceRecords[].name, status.resourceRecords[].type, status.resourceRecords[].rrdata)'

cat <<NEXT

Then:
  - Wait for DNS to propagate; Google auto-issues the TLS cert (can take ~15-60 min).
  - Watch status:
      gcloud beta run domain-mappings describe --region $REGION --domain $DOMAIN \\
        --format='value(status.conditions[].type, status.conditions[].status)'
  - Set the app's allowed origin to the domain and redeploy:
      GATEWAY... DOMAIN=$DOMAIN ./deploy/cloudrun/deploy.sh      # sets CORS_ORIGINS=https://$DOMAIN
  - Point the clients at https://$DOMAIN (extension prod build, palivane-connect, managed policy).
NEXT
