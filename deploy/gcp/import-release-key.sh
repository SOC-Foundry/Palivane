#!/usr/bin/env bash
# Import the existing release signing key into Cloud KMS (security review H10).
#
# Moves the ECDSA P-256 key that signs the CLI release out of Secret Manager and into the
# HSM-backed, import-only KMS key from deploy/terraform/kms.tf, so the deploy pipeline signs
# with KMS and the running service no longer holds the private key. Same key, so every
# installed client keeps verifying against the key it already pins.
#
# Run it as the deploy SA through the ops workflow (it never runs in the container):
#   1. Terraform: dispatch terraform-apply.yml with apply + release_key_import ticked
#      (after a plan-only dispatch looks right).
#   2. gh secret set OPS_RUNNER_SCRIPT < deploy/gcp/import-release-key.sh
#      gh workflow run ops.yml -f note="import release signing key into KMS"
#      gh secret delete OPS_RUNNER_SCRIPT
#   3. Read the output (encrypted to OPS_OUTPUT_GPG_KEY): it ends with the key version to
#      set as the repo variable RELEASE_KMS_KEY_VERSION.
#   4. Dispatch terraform-apply.yml again with release_key_import unticked.
#   5. After a deploy has shown the KMS signatures verifying (deploy.yml checks), disable
#      and destroy the palivane-release-signing-key secret versions.
#
# The key material only ever sits in a 0700 temp dir on the runner, and is removed on exit.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?}"
REGION="${REGION:?}"
RING="${RELEASE_KEY_RING:-palivane-release}"
KEY="${RELEASE_KEY:-release-signing}"
SECRET="${RELEASE_SECRET:-palivane-release-signing-key}"
JOB="release-import-$(date -u +%Y%m%d%H%M%S)"
KMS=(--project "$PROJECT_ID" --location "$REGION" --keyring "$RING")

work="$(mktemp -d)"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

echo "==> Creating import job $JOB"
gcloud kms import-jobs create "$JOB" "${KMS[@]}" \
  --import-method rsa-oaep-3072-sha256-aes-256 --protection-level hsm
for _ in $(seq 1 60); do
  state="$(gcloud kms import-jobs describe "$JOB" "${KMS[@]}" --format 'value(state)')"
  [ "$state" = ACTIVE ] && break
  sleep 5
done
[ "$state" = ACTIVE ] || { echo "import job never became ACTIVE ($state)" >&2; exit 1; }

echo "==> Reading the current release key from Secret Manager ($SECRET)"
gcloud secrets versions access latest --secret "$SECRET" --project "$PROJECT_ID" > "$work/key.pem"
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in "$work/key.pem" -out "$work/key.der"
openssl pkey -in "$work/key.pem" -pubout -outform DER -out "$work/secret-pub.der"

echo "==> Importing it into $RING/$KEY"
gcloud kms keys versions import "${KMS[@]}" --key "$KEY" --import-job "$JOB" \
  --algorithm ec-sign-p256-sha256 --target-key-file "$work/key.der"
rm -f "$work/key.pem" "$work/key.der"

version="$(gcloud kms keys versions list "${KMS[@]}" --key "$KEY" --sort-by '~createTime' \
  --limit 1 --format 'value(name)')"
for _ in $(seq 1 60); do
  state="$(gcloud kms keys versions describe "$version" --format 'value(state)')"
  [ "$state" = ENABLED ] && break
  sleep 5
done
[ "$state" = ENABLED ] || { echo "imported version never became ENABLED ($state)" >&2; exit 1; }

gcloud kms keys versions get-public-key "$version" --output-file "$work/kms-pub.pem"
openssl pkey -pubin -in "$work/kms-pub.pem" -outform DER -out "$work/kms-pub.der"
if ! cmp -s "$work/kms-pub.der" "$work/secret-pub.der"; then
  echo "the imported KMS key's public half is not the secret's — not using it" >&2
  exit 1
fi
fp="sha256:$(sha256sum "$work/kms-pub.der" | cut -c1-16)"
echo "==> Imported. Public key $fp (the key the installer pins, if nothing else changed)."
echo "Set the repo variable:"
echo "  gh variable set RELEASE_KMS_KEY_VERSION --body '$version'"
