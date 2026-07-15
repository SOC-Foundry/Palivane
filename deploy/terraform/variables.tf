variable "project_id" {
  type        = string
  description = "GCP project id."
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "service_name" {
  type    = string
  default = "warden"
}

variable "image" {
  type        = string
  description = "Full container image ref, e.g. us-central1-docker.pkg.dev/PROJECT/warden/warden:TAG. Build/push out-of-band (deploy/cloudrun) or via CI."
}

# --- data / networking ---
variable "subnet_cidr" {
  type    = string
  default = "10.20.0.0/24"
}

variable "psa_range_name" {
  type    = string
  default = "warden-psa"
}

variable "psa_prefix_length" {
  type        = number
  default     = 16
  description = "Prefix length for the private-services-access range Cloud SQL's private IP is drawn from."
}

variable "db_tier" {
  type    = string
  default = "db-f1-micro"
}

variable "db_disk_gb" {
  type    = number
  default = 10
}

variable "db_user" {
  type    = string
  default = "warden"
}

# --- runtime config (non-secret env; secrets come from Secret Manager, see secrets.tf) ---
variable "gateway_enforce" {
  type    = bool
  default = false # monitor by default; confirmed secret/PII leaks still hard-block
}

variable "allow_signup" {
  type    = bool
  default = false # OFF unless you intend an open multi-tenant deployment
}

variable "store_content" {
  type    = bool
  default = false # metadata-only by default (don't persist prompt prose)
}

variable "encrypt_findings" {
  type    = bool
  default = true
}

variable "public_domain" {
  type        = string
  default     = ""
  description = "Public hostname (e.g. warden.example.com). Sets WARDEN_PUBLIC_URL / CORS_ORIGINS."
}

variable "allowed_hosts" {
  type        = string
  default     = ""
  description = "Comma-separated Host allowlist (add the *.run.app host too if a proxy/Worker reaches the origin by it)."
}

variable "extension_id" {
  type        = string
  default     = ""
  description = "Published browser-extension id (adds chrome-extension://<id> to CORS)."
}

variable "smtp_host" {
  type    = string
  default = ""
}

variable "smtp_user" {
  type    = string
  default = ""
}

variable "mail_from" {
  type    = string
  default = ""
}

variable "min_instances" {
  type    = number
  default = 0
}

variable "max_instances" {
  type    = number
  default = 4
}

# Who may invoke the Cloud Run service. NOT allUsers by default — the org's
# domain-restricted-sharing policy forbids it, and public access is fronted by a Cloudflare
# Worker running as a service account. List that SA and/or human users here.
variable "invoker_members" {
  type    = list(string)
  default = []
}
