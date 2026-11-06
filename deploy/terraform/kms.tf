# Release signing key (security review H10). The CLI release manifest is signed in the deploy
# pipeline by this Cloud KMS key, so the running service never holds the private key: a
# compromised backend can't sign a malicious client update.
#
# The key is IMPORT-ONLY: its one version is the existing release key, imported by
# deploy/gcp/import-release-key.sh, so every installed client keeps verifying against the key
# it already pins. HSM-protected; the private half can't be exported once imported.
#
# Who may sign: the release SA (service-accounts.tf) and var.release_signer_members. Who may import:
# var.release_key_importers, set only for the import run and then emptied again. The
# runtime service account gets nothing here.

resource "google_kms_key_ring" "release" {
  name     = "${var.service_name}-release"
  location = var.region

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "release" {
  name                          = "release-signing"
  key_ring                      = google_kms_key_ring.release.id
  purpose                       = "ASYMMETRIC_SIGN"
  import_only                   = true
  skip_initial_version_creation = true
  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "release_signer" {
  for_each      = toset(var.release_signer_members)
  crypto_key_id = google_kms_crypto_key.release.id
  role          = "roles/cloudkms.signerVerifier"
  member        = each.value
}

resource "google_kms_crypto_key_iam_member" "release_importer" {
  for_each      = toset(var.release_key_importers)
  crypto_key_id = google_kms_crypto_key.release.id
  role          = "roles/cloudkms.importer"
  member        = each.value
}
