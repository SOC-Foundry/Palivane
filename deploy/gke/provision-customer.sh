#!/usr/bin/env bash
# Onboard ONE isolated enterprise customer onto the Warden GKE platform:
#   dedicated node pool + dedicated Cloud SQL + dedicated GSA (Terraform), then a
#   single-tenant Warden instance in its own namespace (Helm), on its own subdomain.
#
#   1. add the customer to terraform/*.tfvars `customers` map, then:
#   2. ./provision-customer.sh <slug> <hostname>
#
# Idempotent: re-running reuses the existing WARDEN_SECRET_KEY / DB password from Secret
# Manager (never rotates them — that would orphan encrypted findings). Needs: gcloud,
# kubectl, helm, terraform, python3.
set -euo pipefail

SLUG="${1:?usage: provision-customer.sh <slug> <hostname>}"
HOST="${2:?usage: provision-customer.sh <slug> <hostname>}"
PROJECT="${PROJECT_ID:-erudite-calling-502022-k6}"
REGION="${REGION:-us-central1}"
CLUSTER="${CLUSTER:-warden}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> [1/5] Terraform: create ${SLUG}'s dedicated node pool + Cloud SQL + GSA"
( cd "$HERE/terraform" && terraform apply -input=false -auto-approve -target="module.customer[\"$SLUG\"]" )
read -r GSA CONN < <(cd "$HERE/terraform" && terraform output -json customers | python3 -c "
import json,sys; d=json.load(sys.stdin)['$SLUG']; print(d['gsa_email'], d['sql_connection_name'])")
INSTANCE="warden-$SLUG"
echo "    GSA=$GSA  instance=$INSTANCE"

echo "==> [2/5] cluster credentials + namespace"
gcloud container clusters get-credentials "$CLUSTER" --region "$REGION" --project "$PROJECT" >/dev/null
kubectl create namespace "$SLUG" --dry-run=client -o yaml | kubectl apply -f -

echo "==> [3/5] secrets (reuse if present — never rotate the key)"
sk_secret="warden-$SLUG-secret-key"
db_secret="warden-$SLUG-db-url"
get_or_create() { # $1=secret name, $2=value-if-new
  if gcloud secrets describe "$1" --project "$PROJECT" >/dev/null 2>&1; then
    gcloud secrets versions access latest --secret="$1" --project "$PROJECT"
  else
    printf '%s' "$2" | gcloud secrets create "$1" --project "$PROJECT" --replication-policy=automatic --data-file=- >/dev/null
    printf '%s' "$2"
  fi
}
SECRETKEY="$(get_or_create "$sk_secret" "$(openssl rand -hex 32)")"
if gcloud secrets describe "$db_secret" --project "$PROJECT" >/dev/null 2>&1; then
  DBURL="$(gcloud secrets versions access latest --secret="$db_secret" --project "$PROJECT")"
else
  DBPASS="$(openssl rand -hex 24)"
  gcloud sql users create warden --instance="$INSTANCE" --project "$PROJECT" --password="$DBPASS" 2>/dev/null \
    || gcloud sql users set-password warden --instance="$INSTANCE" --project "$PROJECT" --password="$DBPASS"
  DBURL="postgresql+psycopg2://warden:${DBPASS}@127.0.0.1:5432/warden"   # via the Cloud SQL proxy sidecar
  printf '%s' "$DBURL" | gcloud secrets create "$db_secret" --project "$PROJECT" --replication-policy=automatic --data-file=- >/dev/null
fi

echo "==> [4/5] kubernetes secret"
kubectl -n "$SLUG" create secret generic "warden-$SLUG-secrets" \
  --from-literal=WARDEN_SECRET_KEY="$SECRETKEY" \
  --from-literal=DATABASE_URL="$DBURL" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> [5/5] helm install the single-tenant instance"
helm upgrade --install "warden-$SLUG" "$HERE/chart/warden" -n "$SLUG" \
  --set customer="$SLUG" --set host="$HOST" \
  --set gcpServiceAccount="$GSA" --set cloudsql.connectionName="$CONN"

cat <<EOF

Provisioned '$SLUG'. Next:
  - Point DNS: $HOST -> the ingress IP:  kubectl -n $SLUG get ingress warden-$SLUG
    (the Google-managed cert provisions once DNS resolves; ~15-30 min.)
  - Create the first admin:
      kubectl -n $SLUG exec deploy/warden-$SLUG -c warden -- \\
        python -m app.users create-tenant --slug $SLUG --name "$SLUG"
      kubectl -n $SLUG exec deploy/warden-$SLUG -c warden -- \\
        python -m app.users create-user --tenant $SLUG --email admin@$SLUG.example --role admin
EOF
