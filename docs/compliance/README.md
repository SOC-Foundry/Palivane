# Compliance program

Policy suite and security-questionnaire responses backing the SOC 2 program and the
public [/trust](https://palivane.tachtech.net/trust) page. Every control cited here is
implemented; where a policy names a cadence, the calendar below is the commitment.

**Owner:** David Kerschieter (Founder — acts as CEO, CISO, and DPO). Single-operator
context: separation-of-duties controls are replaced by documented compensating controls
(automation-enforced gates, immutable logs) noted per policy.

| # | Policy | Maps to (SOC 2 TSC) |
|---|--------|---------------------|
| 01 | [Information Security Policy](policies/01-information-security.md) | CC1, CC2, CC5 |
| 02 | [Access Control](policies/02-access-control.md) | CC6 |
| 03 | [Change Management](policies/03-change-management.md) | CC8 |
| 04 | [Incident Response](policies/04-incident-response.md) | CC7.3–CC7.5 |
| 05 | [Business Continuity & DR](policies/05-business-continuity-dr.md) | A1 |
| 06 | [Vendor Management](policies/06-vendor-management.md) | CC9.2 |
| 07 | [Data Classification & Handling](policies/07-data-classification.md) | C1 |
| 08 | [Secure Development](policies/08-secure-development.md) | CC8.1 |
| 09 | [Risk Management](policies/09-risk-management.md) | CC3, CC9.1 |
| 10 | [Acceptable Use & Endpoints](policies/10-acceptable-use-endpoints.md) | CC6.7, CC6.8 |
| 11 | [Data Retention & Disposal](policies/11-data-retention-disposal.md) | C1.2 |

Questionnaire: [CAIQ-style responses](caiq.md) (hand this + the DPA + /trust to reviewers).

## Compliance calendar

| Cadence | Activity | Evidence |
|---|---|---|
| Quarterly | Access review (GCP IAM, GitHub, Cloudflare, Secret Manager, app admins) | dated note in `docs/compliance/reviews/` |
| Semiannual | Backup restore drill (PITR clone + row verification; last: 2026-07-19, ~35 min) | drill log |
| Annual | Policy review + re-approval, risk assessment refresh, security-awareness training | updated docs, dated |
| Annual | Third-party penetration test (first: scheduled under the SOC 2 program) | report |
| Ad hoc | Incident response tabletop (at least one before the Type II window closes) | exercise notes |

## Revision history

- 2026-07-19 — v1.0, initial suite adopted (all policies effective this date).
