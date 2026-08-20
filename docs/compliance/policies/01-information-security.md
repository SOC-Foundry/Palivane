# 01 — Information Security Policy

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Purpose & scope

Defines how Palivane protects Palivane (the hosted service at app.palivane.io, the
source repository, and all customer data processed by either). Applies to every person
with access — currently the Founder and any future employee or contractor from their
first day.

## Objectives

Protect the confidentiality, integrity, and availability of customer data — which for
Palivane includes some of the most sensitive artifacts an organization has (prompts,
findings about leaked credentials, security posture). The product's own design reflects
this: redaction before storage, metadata-only defaults, per-tenant encryption.

## Core commitments

1. **Least privilege** — access is granted per role and reviewed quarterly (Policy 02).
2. **Defense in depth** — controls exist at the edge (Cloudflare WAF), application
   (authn/z, rate limits), and database (Postgres Row-Level Security) layers.
3. **Encryption everywhere** — TLS in transit; disk + application-layer envelope
   encryption at rest (per-tenant data keys).
4. **Change control** — no change reaches production outside the gated flow (Policy 03).
5. **Verified recoverability** — backups exist AND restores are drilled (Policy 05).
6. **Honest disclosure** — incidents and vulnerabilities are handled per Policy 04 and
   `SECURITY.md`; the public /trust page states only implemented controls.

## Organization & accountability

The Founder is accountable for this program (CEO/CISO/DPO roles). Compensating controls
for single-operator risk: automation-enforced gates that the operator cannot bypass
(branch protection with admins enforced, CI-gated merges), immutable audit logging in
the product and cloud provider, and externally attested evidence (uptime probes,
Secret Manager access logs). Policy exceptions must be written down in
`docs/compliance/exceptions.md` with rationale and expiry; none exist today.

## Personnel security

Any future hire: background check before access, security-awareness training within 30
days and annually after, offboarding checklist (all access revoked same day). The
Founder completes annual training and a self background check for the audit record.

## Enforcement & review

Violations by future personnel are grounds for access revocation and termination. This
policy and its children are reviewed and re-approved annually or after material
architecture changes.
