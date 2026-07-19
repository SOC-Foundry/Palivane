# 04 — Incident Response Plan

**Owner:** Founder (Incident Commander) · **Effective:** 2026-07-19 · **Review:** annual + post-incident

## What counts as an incident

Confirmed or suspected: unauthorized access to customer data, tenant-isolation failure,
credential/secret exposure, malicious code in the supply chain, sustained availability
loss, or a report to security@tachtech.net that reproduces.

## Severities

- **SEV-1** — customer data exposed or isolation broken. All-hands (of one), immediate.
- **SEV-2** — exploitable vulnerability, no evidence of exposure; or full outage.
- **SEV-3** — degraded service, hardening gap, non-reproducing report.

## Response steps

1. **Detect** — uptime alerts (email), Cloud Run/Cloud SQL logs, Warden's own audit
   log and findings, security@tachtech.net reports.
2. **Contain** — revoke/rotate affected credentials (Secret Manager versions, API key
   revocation, `logout-all`, agent disable — all built for this); suspend affected
   tenants if needed; shift Cloud Run traffic to a known-good revision.
3. **Eradicate & recover** — fix-forward through the change gate; restore from PITR if
   data integrity is in question (Policy 05).
4. **Record** — timeline, blast radius, root cause, and actions in
   `docs/compliance/incidents/<date>-<slug>.md`. Every SEV-1/2 gets a written
   post-mortem with remediation items tracked to closure.

## Notification

- **Customers:** affected orgs notified without undue delay and within **72 hours** of
  confirming their data was involved — what happened, what was exposed, what we did,
  what they should do. Contact = org admin emails.
- **Regulators/processors:** per DPA commitments; subprocessor incidents flow through
  (Policy 06).
- No public minimization: the /trust page gets a factual note for SEV-1s.

## Precedent on file

2026-07-16 — suspected DB credential exposure in a chat context; password rotated and
service redeployed same day, no evidence of access. Handled per steps 2–4 before this
plan was formalized; recorded as the model.

## Exercises

At least one tabletop per audit period (scenario: leaked capture key + tenant-isolation
claim), notes filed with the incident records.
