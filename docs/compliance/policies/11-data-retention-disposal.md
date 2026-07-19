# 11 — Data Retention & Disposal

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Retention schedule

| Data | Retention | Mechanism |
|---|---|---|
| Findings (per org) | Customer-controlled: N days or forever (`retention_days`) | automated purge job |
| Usage metering minute-buckets | ~35 days | automated prune |
| Audit logs (in-product) | Life of the org | deleted with the org |
| Cloud SQL backups / PITR | 14 days rolling | Cloud SQL automated |
| Cloud logging | Provider default (30 days) | GCP |
| Abandoned empty signups | Purged after 30 days | `purge-empty` CLI (operator-run) |

## Customer-controlled disposal

- **Export:** self-serve full-org JSON export (secrets never included; content
  decrypted only when explicitly requested by an org admin).
- **Deletion:** self-serve org deletion removes every row the org owns — findings,
  users, keys, audit log, domains, SSO config, usage — verified by the lifecycle test
  suite. Backups age out within 14 days; the DPA states this window.
- **Crypto-shredding:** content is sealed under a per-tenant DEK; dropping the wrapped
  DEK renders remaining ciphertext unrecoverable independent of row deletion.

## Media & credentials

No physical media exists (fully cloud-hosted). Retired credentials are destroyed, not
archived: Secret Manager versions disabled/destroyed on rotation, API keys revoked
(hashes retained only as tombstones), agent tokens expire on their own (≤24 h).
