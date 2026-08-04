# Security questionnaire responses (CAIQ-style)

Pre-filled answers to the questions security reviewers ask most, organized by CAIQ v4
domain. Hand this with the [/trust](https://warden.tachtech.net/trust) page and the
in-product DPA. Company: **TachTech** · Service: **Palivane — AI Security Gateway**
(hosted at warden.tachtech.net; self-hosted option available). Current as of
**2026-07-19**; contact security@tachtech.net.

**Context reviewers should know up front:** TachTech is a single-operator company. We
compensate with automation-enforced controls (CI-gated protected-branch changes that
admins cannot bypass, immutable audit logs, externally attested monitoring) rather than
headcount-based separation of duties. Our SOC 2 Type II program is underway.

## A&A — Audit & Assurance

| Q | Answer |
|---|---|
| Independent audits/attestations? | SOC 2 Type II program underway (Type I expected first). Two internal multi-perspective adversarial security audits completed July 2026, all findings remediated. Third-party penetration test scheduled. |
| Will you complete customer questionnaires / allow due-diligence calls? | Yes — this document, the DPA, and a call on request. |

## AIS — Application & Interface Security

| Q | Answer |
|---|---|
| SDLC with security testing? | Yes — 700+ automated tests including dedicated tenant-isolation, authn/z, SSRF, redaction, and encryption suites; CI must pass before any change reaches `main` (branch protection, admins enforced). |
| Input validation? | Schema validation (Pydantic) at every API boundary; size caps; SSRF guards on all customer-supplied URLs at write AND send time. |
| API security | All APIs authenticated (JWT sessions, hashed API keys, short-lived agent tokens); per-tenant and per-agent rate limits; per-IP edge limits on auth endpoints. |
| Vulnerability disclosure? | Public policy in SECURITY.md — security@tachtech.net, ack ≤ 2 business days, 90-day coordinated disclosure. |

## BCR — Business Continuity & Operational Resilience

| Q | Answer |
|---|---|
| Documented BC/DR plan? | Yes (Policy 05). RPO ≤ 24 h nominal (PITR gives minutes typical); RTO ≈ 1 h. |
| Backups tested? | Yes — restore drills semiannually; most recent 2026-07-19: full PITR clone restored and verified row-by-row in ~35 minutes. |
| Availability monitoring? | External multi-region uptime probes on the health endpoint every minute, alerting to on-call email. |

## CCC — Change Control & Configuration

| Q | Answer |
|---|---|
| Formal change management? | Yes — every production change is a PR against a protected branch requiring passing CI (tests, build, whole-stack boot, Terraform validate); linear history; no force pushes; admins not exempt. |
| Separation of duties? | Single operator — compensating controls documented (automation-enforced gate, immutable PR/audit history); approvals raise to ≥1 human with first hire. |
| Infrastructure as code? | Yes — Terraform owns the infra shell (state in GCS); edge Worker config version-controlled. |

## CEK — Cryptography, Encryption & Key Management

| Q | Answer |
|---|---|
| Encryption in transit? | TLS at the Cloudflare edge for all public traffic; origin calls are IAM-authenticated service-to-service (Google-signed tokens). |
| Encryption at rest? | Cloud SQL disk encryption plus application-layer envelope encryption of finding content under per-tenant data keys (Fernet; wrapped DEKs). |
| Key management? | All keys/secrets in Google Secret Manager; per-tenant DEKs wrapped by a master key; provider keys stored encrypted per tenant; API keys stored as SHA-256 hashes only. License signing key (Ed25519) held vendor-side only. |
| Customer data crypto-shreddable? | Yes — dropping an org's wrapped DEK renders its encrypted content unrecoverable. |

## DCS — Datacenter Security

| Q | Answer |
|---|---|
| Physical security? | Inherited from Google Cloud (us-central1) — SOC 2/ISO 27001 attested. TachTech operates no physical infrastructure. |

## DSP — Data Security & Privacy Lifecycle

| Q | Answer |
|---|---|
| Data classification policy? | Yes (Policy 07) — with product-enforced handling: secrets redacted and PII masked **before** storage; metadata-only by default; full content storage is per-org opt-in and per-tenant encrypted. |
| Tenant isolation? | Application-level scoping **plus** Postgres Row-Level Security enforced in the database on every tenant-scoped table. |
| Data residency? | us-central1 (US). Self-hosted deployments keep all data in customer infrastructure. |
| Customer data deletion/export? | Self-serve full JSON export and self-serve complete org deletion; backups age out ≤ 14 days. DPA presented in-product with versioned acceptance. |
| Is customer data used for training? | No. The optional LLM judge (Anthropic, per-org opt-out) is API-only; Anthropic does not train on API data. |

## GRC — Governance, Risk & Compliance

| Q | Answer |
|---|---|
| Security policies maintained? | Yes — 11-policy suite (docs/compliance/), owner-approved, reviewed annually, versioned in git. |
| Risk assessments? | Yes — maintained risk register (Policy 09) updated on material change; inputs from audits, incidents, and pen tests. |

## HRS — Human Resources

| Q | Answer |
|---|---|
| Background checks / training / confidentiality? | Single founder today (background check on file for the audit; annual security-awareness training). All requirements apply to future hires from day one; same-day offboarding checklist defined. |

## IAM — Identity & Access Management

| Q | Answer |
|---|---|
| MFA? | Enforced on all operator accounts (GCP, GitHub, Cloudflare); TOTP MFA available to all product users; SSO (OIDC + SAML) per organization. |
| Least privilege / RBAC? | Admin/analyst roles in-product; least-privilege agent roles with allow/deny policies; single-purpose service accounts in the cloud. |
| Access reviews? | Quarterly, documented (Policy 02). |
| Session management? | Revocable JWT sessions (token_version), brute-force throttling, short-lived (≤24 h) agent session tokens revoked instantly on agent disable. |

## IPY — Interoperability & Portability

| Q | Answer |
|---|---|
| Can customers export data in standard formats? | Yes — full-org JSON export self-serve; findings also stream to customer SIEM (Splunk HEC/CEF/JSON) and S3. |
| Lock-in mitigations? | Self-hosted deployment option with the same codebase and license mechanism. |

## LOG — Logging & Monitoring

| Q | Answer |
|---|---|
| Audit logging? | In-product per-org audit log of administrative actions (visible to customers); GCP audit/infra logs; Secret Manager access logging. |
| Log protection? | Logs are append-only to users; no customer-content in operator logs (redaction happens before storage; logging uses IDs/metadata). |
| Security monitoring/alerting? | Uptime alerting; cloud log review during incidents; the product's own detection surfaces anomalous AI usage in our dogfood org. |

## SEF — Security Incident Management

| Q | Answer |
|---|---|
| Documented IR plan? | Yes (Policy 04) — severities, containment runbooks (credential rotation, session revocation, tenant suspension, revision rollback), written post-mortems. |
| Customer breach notification SLA? | Without undue delay, ≤ 72 h from confirming an org's data was involved. |
| Incidents to date? | One precautionary credential rotation (2026-07-16, suspected exposure, no evidence of access) — handled and recorded. |

## STA — Supply Chain Management

| Q | Answer |
|---|---|
| Subprocessor list published? | Yes — /trust page and Policy 06 (GCP, Cloudflare, Anthropic, Google Workspace), all SOC 2 attested. |
| Vendor review process? | Attestation + least-privilege scoping before adoption; annual review (Policy 06). |
| Software supply chain? | Minimal dependencies (CLI tools deliberately stdlib-only), lockfiles, CI gate, dependency-risk scanning (our own detector + OSV). |

## TVM — Threat & Vulnerability Management

| Q | Answer |
|---|---|
| Vulnerability management program? | Dependency alerts triaged on arrival; security fixes ship same-day through the change gate (history: all July 2026 audit findings remediated with regression tests). |
| Penetration testing? | Internal adversarial audits July 2026 (remediated); independent pen test scheduled under the SOC 2 program. |
| Endpoint protection? | Policy 10: FDE, auto-update, screen lock, MFA — continuously evidenced by dogfooding Palivane's own posture sensors on the operator's machine. |
