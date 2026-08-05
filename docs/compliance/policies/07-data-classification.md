# 07 — Data Classification & Handling

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Classes

| Class | Examples | Handling |
|---|---|---|
| **Restricted** | Finding content, scanned prompts/args, secrets material handled by detectors, per-tenant DEKs, the vendor license signing key, provider keys | Redacted before storage; encrypted at rest under per-tenant keys; keys in Secret Manager only; never in logs, tickets, or chat |
| **Confidential** | Customer identities (emails, org names), audit logs, usage metrics, license blobs | Encrypted at rest (disk); access via authenticated, tenant-scoped APIs only |
| **Internal** | Source code, runbooks, this policy suite | Private repo, access-controlled |
| **Public** | Marketing site, docs, /trust, published extensions | No restriction |

## Product-enforced handling of Restricted data

These are code paths, not habits:

- **Redaction-first:** detected secrets become `«redacted:label»` and PII is masked
  *before* a finding row is written (`PALIVANE_REDACT_FINDINGS`, default on).
- **Metadata-only default:** raw prompt prose is stored only if an org opts in
  (`store_content`), and then encrypted under that org's DEK (`enc:v2`).
- **Evidence minimization:** signal evidence carries labels or short prefixes, never
  full secret values. API keys are stored as SHA-256 hashes; MFA/SSO secrets encrypted.
- **Isolation:** Postgres RLS keeps every tenant-scoped row invisible outside its org.

## Movement rules

Restricted data never leaves production systems except: (a) to the org's own
configured integrations (SIEM/S3/webhooks — their credentials, their destination);
(b) to Anthropic for judging when the org allows it. Operator debugging uses
metadata and IDs, not content; where content access is unavoidable it runs as an
auditable one-off job and is noted in the audit log.
